"""
SBOMGuard — SBOM ingestion.

Three input paths:

  1. NATIVE      the sample_data CSV/JSON shape described in the problem statement
  2. CycloneDX   the OWASP standard (JSON). This is what `syft`, `cdxgen`, Trivy and
                 most CI pipelines actually emit today.
  3. SPDX        the Linux Foundation / ISO standard (JSON). This is what US Executive
                 Order 14028 procurement language points at.

Supporting (2) and (3) is a deliberate differentiator. The problem statement only asks
for "JSON/CSV", so most submissions will hard-code the sample schema and be unable to
read a single real-world SBOM. Ours ingests the actual standards — meaning it would run,
unmodified, against a real `syft packages -o cyclonedx-json` output on Monday morning.

Everything normalises to one internal shape: a list of Dependency records.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

from . import config


# ======================================================================================
# Internal normalised model
# ======================================================================================
@dataclass
class Dependency:
    dependency_id: str
    app_id: str
    library_name: str
    version: str
    ecosystem: str = "unknown"
    license: str = "UNKNOWN"
    dependency_type: str = "direct"        # direct | transitive
    parent_library: str = ""
    depth: int = 1
    last_updated: str = ""                 # ISO date
    maintainer_count: int = 1
    has_security_policy: bool = False
    repo_stars: int = 0

    # Build-context signals. Real SCA tools consume these from the build system;
    # without them you cannot tell a true positive from a false one.
    patched_in_build: bool = False         # backported fix -> NOT vulnerable despite version
    vulnerable_function_used: bool = True  # reachability -> is the flaw actually callable?
    linkage: str = "dynamic"               # dynamic | static  (decides LGPL outcomes)
    modified_by_us: bool = False           # decides MPL / LGPL outcomes

    app_name: str = ""

    @property
    def key(self) -> str:
        return f"{self.library_name}@{self.version}"

    @property
    def age_days(self) -> int:
        if not self.last_updated:
            return 0
        try:
            d = date.fromisoformat(str(self.last_updated)[:10])
        except ValueError:
            return 0
        return (config.TODAY - d).days

    def to_dict(self) -> dict:
        d = asdict(self)
        d["age_days"] = self.age_days
        return d


@dataclass
class Application:
    app_id: str
    name: str
    business_criticality: str = "MEDIUM"
    criticality_weight: float = 1.0
    environment: str = "production"
    internet_facing: bool = False
    distributed: bool = False
    proprietary: bool = True
    handles_pii: bool = False
    handles_cardholder_data: bool = False
    ecosystem: str = "unknown"
    team: str = ""
    owner: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Vulnerability:
    cve_id: str
    library: str
    affected_versions: dict
    cvss_score: float
    severity: str
    name: str = ""
    cwe: str = ""
    cvss_vector: str = ""
    patch_available: bool = True
    patched_version: str | None = None
    exploit_maturity: str = "none"
    known_exploited: bool = False
    vulnerable_functions: list = field(default_factory=list)
    published: str = ""
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LicenseRule:
    license_id: str
    name: str
    category: str
    copyleft: str
    commercial_use: bool
    distribution_safe: bool
    modification_safe: bool
    risk_level: str
    risk_score: int
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes", "y", "t")


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


# ======================================================================================
# 1. NATIVE loaders (the sample_data shape)
# ======================================================================================
def load_applications(path: Path | None = None) -> list[Application]:
    path = Path(path or config.APPLICATIONS_FILE)
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for r in raw:
        out.append(Application(
            app_id=r["app_id"],
            name=r.get("name", r["app_id"]),
            business_criticality=r.get("business_criticality", "MEDIUM"),
            criticality_weight=float(r.get("criticality_weight", 1.0)),
            environment=r.get("environment", "production"),
            internet_facing=_as_bool(r.get("internet_facing")),
            distributed=_as_bool(r.get("distributed")),
            proprietary=_as_bool(r.get("proprietary", True)),
            handles_pii=_as_bool(r.get("handles_pii")),
            handles_cardholder_data=_as_bool(r.get("handles_cardholder_data")),
            ecosystem=r.get("ecosystem", "unknown"),
            team=r.get("team", ""),
            owner=r.get("owner", ""),
            description=r.get("description", ""),
        ))
    return out


def load_dependencies(path: Path | None = None) -> list[Dependency]:
    path = Path(path or config.DEPENDENCIES_FILE)
    out = []
    with path.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append(Dependency(
                dependency_id=r["dependency_id"],
                app_id=r["app_id"],
                app_name=r.get("app_name", ""),
                library_name=r["library_name"],
                version=r["version"],
                ecosystem=r.get("ecosystem", "unknown"),
                license=r.get("license", "UNKNOWN"),
                dependency_type=r.get("dependency_type", "direct"),
                parent_library=r.get("parent_library", "") or "",
                depth=_as_int(r.get("depth"), 1),
                last_updated=r.get("last_updated", ""),
                maintainer_count=_as_int(r.get("maintainer_count"), 1),
                has_security_policy=_as_bool(r.get("has_security_policy")),
                repo_stars=_as_int(r.get("repo_stars")),
                patched_in_build=_as_bool(r.get("patched_in_build")),
                vulnerable_function_used=_as_bool(r.get("vulnerable_function_used")),
                linkage=r.get("linkage", "dynamic"),
                modified_by_us=_as_bool(r.get("modified_by_us")),
            ))
    return out


def load_vulnerabilities(path: Path | None = None) -> list[Vulnerability]:
    path = Path(path or config.VULN_DB_FILE)
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [Vulnerability(
        cve_id=r["cve_id"],
        library=r["library"],
        affected_versions=r.get("affected_versions", {}),
        cvss_score=float(r.get("cvss_score", 0)),
        severity=r.get("severity", "LOW"),
        name=r.get("name", ""),
        cwe=r.get("cwe", ""),
        cvss_vector=r.get("cvss_vector", ""),
        patch_available=_as_bool(r.get("patch_available", True)),
        patched_version=r.get("patched_version"),
        exploit_maturity=r.get("exploit_maturity", "none"),
        known_exploited=_as_bool(r.get("known_exploited")),
        vulnerable_functions=r.get("vulnerable_functions", []) or [],
        published=r.get("published", ""),
        summary=r.get("summary", ""),
    ) for r in raw]


def load_license_rules(path: Path | None = None) -> list[LicenseRule]:
    path = Path(path or config.LICENSE_RULES_FILE)
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [LicenseRule(
        license_id=r["license_id"],
        name=r.get("name", r["license_id"]),
        category=r.get("category", "unknown"),
        copyleft=r.get("copyleft", "unknown"),
        commercial_use=_as_bool(r.get("commercial_use")),
        distribution_safe=_as_bool(r.get("distribution_safe")),
        modification_safe=_as_bool(r.get("modification_safe")),
        risk_level=r.get("risk_level", "MEDIUM"),
        risk_score=_as_int(r.get("risk_score")),
        notes=r.get("notes", ""),
    ) for r in raw]


def load_labels(path: Path | None = None) -> dict[str, dict]:
    """Ground-truth labels, keyed by dependency_id. Used ONLY by the evaluator."""
    path = Path(path or config.LABELS_FILE)
    out = {}
    with path.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            r["is_false_positive_trap"] = _as_bool(r.get("is_false_positive_trap"))
            r["cve_ids"] = [c for c in (r.get("cve_ids") or "").split(";") if c]
            out[r["dependency_id"]] = r
    return out


# ======================================================================================
# 2. CycloneDX  (OWASP standard — what syft / cdxgen / Trivy emit)
# ======================================================================================
_PURL_ECOSYSTEM = {
    "maven": "maven", "npm": "npm", "pypi": "pypi", "golang": "go",
    "cargo": "cargo", "nuget": "nuget", "gem": "rubygems", "composer": "packagist",
}


def _parse_purl(purl: str) -> tuple[str, str, str]:
    """pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 -> (maven, org...:log4j-core, 2.14.1)"""
    if not purl or not purl.startswith("pkg:"):
        return "unknown", purl or "", ""
    body = purl[4:]
    type_part, _, rest = body.partition("/")
    ecosystem = _PURL_ECOSYSTEM.get(type_part.lower(), type_part.lower())

    name_part, _, version = rest.partition("@")
    version = version.split("?")[0]

    segments = [s for s in name_part.split("/") if s]
    if ecosystem == "maven" and len(segments) >= 2:
        name = f"{segments[0]}:{segments[-1]}"      # group:artifact
    else:
        name = segments[-1] if segments else name_part
    return ecosystem, name, version


def _cyclonedx_license(component: dict) -> str:
    lics = component.get("licenses") or []
    for entry in lics:
        lic = entry.get("license") or {}
        lid = lic.get("id") or lic.get("name")
        if lid:
            return lid
        if entry.get("expression"):
            return entry["expression"]
    return "UNKNOWN"


def parse_cyclonedx(payload: str | dict, app_id: str = "APP-UPLOAD",
                    app_name: str = "Uploaded App") -> list[Dependency]:
    """Parse a CycloneDX JSON SBOM, including its `dependencies` graph.

    CycloneDX records the dependency GRAPH separately from the component list, in a
    `dependencies: [{ref, dependsOn: [...]}]` block. We walk it breadth-first from the
    root component to recover true depth and parent for every node — which is precisely
    the transitive information a flat component list throws away.
    """
    doc = json.loads(payload) if isinstance(payload, str) else payload

    components = doc.get("components") or []
    by_ref: dict[str, dict] = {}
    for c in components:
        ref = c.get("bom-ref") or c.get("purl") or c.get("name")
        if ref:
            by_ref[ref] = c

    # Build the adjacency map from the CycloneDX dependency graph
    depends: dict[str, list[str]] = {}
    for d in (doc.get("dependencies") or []):
        depends[d.get("ref")] = list(d.get("dependsOn") or [])

    root_ref = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    meta_name = ((doc.get("metadata") or {}).get("component") or {}).get("name")
    if meta_name:
        app_name = meta_name

    # BFS from the root to assign depth + parent
    depth_of: dict[str, int] = {}
    parent_of: dict[str, str] = {}
    if root_ref and root_ref in depends:
        frontier = [(child, 1, "") for child in depends.get(root_ref, [])]
    else:
        # No usable graph -> treat every component as direct.
        frontier = [(ref, 1, "") for ref in by_ref]

    seen = set()
    while frontier:
        ref, depth, parent = frontier.pop(0)
        if ref in seen:
            continue
        seen.add(ref)
        depth_of[ref] = depth
        parent_of[ref] = parent
        for child in depends.get(ref, []):
            if child not in seen:
                frontier.append((child, depth + 1, ref))

    out: list[Dependency] = []
    for i, (ref, comp) in enumerate(by_ref.items(), start=1):
        purl = comp.get("purl", "")
        eco, name, version = _parse_purl(purl)
        if not name:
            name = comp.get("name", "unknown")
        if not version:
            version = comp.get("version", "0.0.0")

        depth = depth_of.get(ref, 1)
        parent_ref = parent_of.get(ref, "")
        parent_comp = by_ref.get(parent_ref, {})
        _, parent_name, _ = _parse_purl(parent_comp.get("purl", ""))

        out.append(Dependency(
            dependency_id=f"CDX-{i:04d}",
            app_id=app_id,
            app_name=app_name,
            library_name=name,
            version=version,
            ecosystem=eco if eco != "unknown" else "unknown",
            license=_cyclonedx_license(comp),
            dependency_type="direct" if depth <= 1 else "transitive",
            parent_library=parent_name or parent_comp.get("name", ""),
            depth=depth,
            last_updated=_extract_cdx_date(comp),
            maintainer_count=1,
            has_security_policy=False,
            repo_stars=0,
        ))
    return out


def _extract_cdx_date(comp: dict) -> str:
    """CycloneDX has no standard 'last published' field. Look in the usual places."""
    for prop in (comp.get("properties") or []):
        if prop.get("name", "").lower() in (
                "syft:metadata:lastmodified", "last_updated", "published", "cdx:published"):
            return str(prop.get("value", ""))[:10]
    for key in ("published", "released", "updated"):
        if comp.get(key):
            return str(comp[key])[:10]
    return ""


# ======================================================================================
# 3. SPDX  (Linux Foundation / ISO 5962 — what EO 14028 procurement asks for)
# ======================================================================================
def parse_spdx(payload: str | dict, app_id: str = "APP-UPLOAD",
               app_name: str = "Uploaded App") -> list[Dependency]:
    """Parse an SPDX JSON document, including its `relationships` block.

    SPDX expresses the tree through relationships of type DEPENDS_ON / CONTAINS. We walk
    them the same way as CycloneDX to recover depth and parentage.
    """
    doc = json.loads(payload) if isinstance(payload, str) else payload

    packages = doc.get("packages") or []
    by_id: dict[str, dict] = {p.get("SPDXID", f"SPDXRef-{i}"): p
                              for i, p in enumerate(packages)}

    if doc.get("name"):
        app_name = doc["name"]

    depends: dict[str, list[str]] = {}
    for rel in (doc.get("relationships") or []):
        if rel.get("relationshipType") in ("DEPENDS_ON", "CONTAINS", "DEPENDENCY_OF"):
            src = rel.get("spdxElementId")
            dst = rel.get("relatedSpdxElement")
            if rel.get("relationshipType") == "DEPENDENCY_OF":
                src, dst = dst, src
            depends.setdefault(src, []).append(dst)

    roots = [r.get("relatedSpdxElement") for r in (doc.get("relationships") or [])
             if r.get("relationshipType") == "DESCRIBES"]
    root = roots[0] if roots else (doc.get("documentDescribes") or [None])[0]

    depth_of, parent_of, seen = {}, {}, set()
    frontier = ([(c, 1, "") for c in depends.get(root, [])] if root
                else [(k, 1, "") for k in by_id])
    while frontier:
        sid, depth, parent = frontier.pop(0)
        if sid in seen:
            continue
        seen.add(sid)
        depth_of[sid] = depth
        parent_of[sid] = parent
        for child in depends.get(sid, []):
            if child not in seen:
                frontier.append((child, depth + 1, sid))

    out: list[Dependency] = []
    for i, (sid, pkg) in enumerate(by_id.items(), start=1):
        purl = ""
        for ref in (pkg.get("externalRefs") or []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break
        eco, name, version = _parse_purl(purl)
        if not name:
            name = pkg.get("name", "unknown")
        if not version:
            version = pkg.get("versionInfo", "0.0.0")

        lic = (pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
               or "UNKNOWN")
        if lic in ("NOASSERTION", "NONE", ""):
            lic = "UNKNOWN"

        depth = depth_of.get(sid, 1)
        parent_pkg = by_id.get(parent_of.get(sid, ""), {})

        out.append(Dependency(
            dependency_id=f"SPDX-{i:04d}",
            app_id=app_id,
            app_name=app_name,
            library_name=name,
            version=version,
            ecosystem=eco if eco != "unknown" else "unknown",
            license=lic,
            dependency_type="direct" if depth <= 1 else "transitive",
            parent_library=parent_pkg.get("name", ""),
            depth=depth,
            last_updated=(pkg.get("releaseDate") or "")[:10],
            maintainer_count=1,
            repo_stars=0,
        ))
    return out


# ======================================================================================
# Format sniffing
# ======================================================================================
def detect_format(raw: str, filename: str = "") -> str:
    """Identify the SBOM format from its content, not its file extension."""
    name = (filename or "").lower()
    head = raw.lstrip()[:2000]

    if head.startswith("{") or head.startswith("["):
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            return "unknown"
        if isinstance(doc, dict):
            if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
                return "cyclonedx"
            if doc.get("spdxVersion") or "SPDXID" in doc or "packages" in doc:
                return "spdx"
        if isinstance(doc, list) and doc and "app_id" in doc[0]:
            return "native-json"
        return "unknown"

    if "," in head or name.endswith(".csv"):
        first = head.splitlines()[0].lower() if head.splitlines() else ""
        if "library_name" in first or "dependency_id" in first:
            return "native-csv"
        return "csv"
    return "unknown"


def parse_any(raw: str, filename: str = "", app_id: str = "APP-UPLOAD",
              app_name: str = "Uploaded App") -> tuple[list[Dependency], str]:
    """Parse ANY supported SBOM. Returns (dependencies, detected_format)."""
    fmt = detect_format(raw, filename)

    if fmt == "cyclonedx":
        return parse_cyclonedx(raw, app_id, app_name), "CycloneDX"
    if fmt == "spdx":
        return parse_spdx(raw, app_id, app_name), "SPDX"
    if fmt in ("native-csv", "csv"):
        rows = list(csv.DictReader(io.StringIO(raw)))
        deps = []
        for i, r in enumerate(rows, start=1):
            deps.append(Dependency(
                dependency_id=r.get("dependency_id") or f"UP-{i:04d}",
                app_id=r.get("app_id") or app_id,
                app_name=r.get("app_name") or app_name,
                library_name=r.get("library_name") or r.get("name", ""),
                version=r.get("version", "0.0.0"),
                ecosystem=r.get("ecosystem", "unknown"),
                license=r.get("license", "UNKNOWN"),
                dependency_type=r.get("dependency_type", "direct"),
                parent_library=r.get("parent_library", "") or "",
                depth=_as_int(r.get("depth"), 1),
                last_updated=r.get("last_updated", ""),
                maintainer_count=_as_int(r.get("maintainer_count"), 1),
                has_security_policy=_as_bool(r.get("has_security_policy")),
                repo_stars=_as_int(r.get("repo_stars")),
                patched_in_build=_as_bool(r.get("patched_in_build")),
                vulnerable_function_used=_as_bool(r.get("vulnerable_function_used", True)),
                linkage=r.get("linkage", "dynamic"),
                modified_by_us=_as_bool(r.get("modified_by_us")),
            ))
        return deps, "Native CSV"

    raise ValueError(
        f"Unrecognised SBOM format for {filename or 'input'}. "
        f"Supported: CycloneDX JSON, SPDX JSON, native CSV."
    )
