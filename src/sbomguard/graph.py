"""
SBOMGuard — the dependency graph.

This module is the load-bearing wall of the whole project.

The problem statement's hardest-sounding success criterion is "Transitive Resolution:
100%". It is also the EASIEST one to guarantee, provided you model the problem as a graph
instead of a list. Reachability in a directed graph is not a heuristic — it is a decided
question. If the edges are right, the answer is right, every time.

That is why we build a real DiGraph rather than scanning a flat CSV:

    Application  --depends_on-->  Library  --depends_on-->  Library ...

and then answer questions by traversal:

  * "which applications can reach log4j-core?"     -> ancestors of the node
  * "by exactly what path?"                        -> all_simple_paths
  * "are there several routes to the same flaw?"   -> diamond dependency
  * "if this library were backdoored, what falls?" -> descendants / blast radius

Because the graph is per-application (an app's copy of `lodash` is not the same node as
another app's), we namespace library nodes by app. A GLOBAL library graph is maintained
alongside it for cross-application correlation ("who else ships this?").
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

import networkx as nx

from .ingest import Application, Dependency


APP_PREFIX = "app::"
LIB_PREFIX = "lib::"


def app_node(app_id: str) -> str:
    return f"{APP_PREFIX}{app_id}"


def lib_node(app_id: str, library: str, version: str) -> str:
    # Namespaced per app: APP-001's lodash@4.17.15 and APP-002's lodash@4.17.21 are
    # genuinely different risks and must not be collapsed into one node.
    return f"{LIB_PREFIX}{app_id}::{library}@{version}"


@dataclass
class DependencyPath:
    """One concrete route from an application down to a library."""
    app_id: str
    app_name: str
    nodes: list          # ordered library names, app-root excluded
    versions: list
    depth: int

    def as_chain(self) -> str:
        parts = [f"{n}@{v}" for n, v in zip(self.nodes, self.versions)]
        return f"{self.app_name} -> " + " -> ".join(parts)

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "app_name": self.app_name,
            "chain": self.as_chain(),
            "nodes": self.nodes,
            "versions": self.versions,
            "depth": self.depth,
        }


class DependencyGraph:
    """A directed graph of applications and their (transitive) dependencies."""

    def __init__(self, applications: list[Application], dependencies: list[Dependency]):
        self.applications = {a.app_id: a for a in applications}
        self.dependencies = dependencies
        self.G = nx.DiGraph()
        self._build()

    # ---------------------------------------------------------------------------------
    # Construction
    # ---------------------------------------------------------------------------------
    def _build(self) -> None:
        # 1. Application roots
        for app in self.applications.values():
            self.G.add_node(app_node(app.app_id), kind="application",
                            app_id=app.app_id, label=app.name,
                            criticality=app.business_criticality)

        # 2. Library nodes
        # An app can legitimately carry the SAME library at two versions (a diamond with a
        # version conflict). We index by (app, library) -> [versions] to detect that.
        by_app_lib: dict[tuple[str, str], list[Dependency]] = defaultdict(list)
        for dep in self.dependencies:
            n = lib_node(dep.app_id, dep.library_name, dep.version)
            self.G.add_node(
                n, kind="library", app_id=dep.app_id,
                library=dep.library_name, version=dep.version,
                label=f"{dep.library_name}@{dep.version}",
                license=dep.license, ecosystem=dep.ecosystem,
                depth=dep.depth, dependency_id=dep.dependency_id,
                dependency_type=dep.dependency_type,
                last_updated=dep.last_updated, age_days=dep.age_days,
                maintainer_count=dep.maintainer_count,
                patched_in_build=dep.patched_in_build,
                vulnerable_function_used=dep.vulnerable_function_used,
                linkage=dep.linkage, modified_by_us=dep.modified_by_us,
            )
            by_app_lib[(dep.app_id, dep.library_name)].append(dep)

        # 3. Edges
        # Resolve a parent NAME to the concrete parent NODE within the same application.
        parent_index: dict[tuple[str, str], str] = {}
        for dep in self.dependencies:
            parent_index.setdefault((dep.app_id, dep.library_name),
                                    lib_node(dep.app_id, dep.library_name, dep.version))

        for dep in self.dependencies:
            child = lib_node(dep.app_id, dep.library_name, dep.version)

            if dep.dependency_type == "direct" or not dep.parent_library:
                # Direct dependency: the application depends on it.
                self.G.add_edge(app_node(dep.app_id), child, relation="depends_on")
                continue

            parent = parent_index.get((dep.app_id, dep.parent_library))
            if parent and parent != child:
                self.G.add_edge(parent, child, relation="depends_on")
            else:
                # Parent named but not present in the SBOM (a genuinely common defect in
                # real SBOMs). Do not drop the node — attach it to the app and flag it,
                # otherwise we would silently lose a vulnerable component.
                self.G.add_edge(app_node(dep.app_id), child,
                                relation="depends_on", orphaned_parent=dep.parent_library)
                self.G.nodes[child]["orphaned"] = True

    # ---------------------------------------------------------------------------------
    # Queries
    # ---------------------------------------------------------------------------------
    def library_nodes(self, app_id: str | None = None):
        for n, d in self.G.nodes(data=True):
            if d.get("kind") != "library":
                continue
            if app_id and d.get("app_id") != app_id:
                continue
            yield n, d

    def apps_using(self, library: str, version: str | None = None) -> list[str]:
        """Every application that reaches `library`, directly OR transitively.

        This is the Log4Shell question, and it is answered by graph reachability, not by
        a substring search over a list of direct dependencies.
        """
        hits = set()
        for n, d in self.library_nodes():
            if d["library"] != library:
                continue
            if version and d["version"] != version:
                continue
            root = app_node(d["app_id"])
            if root in self.G and nx.has_path(self.G, root, n):
                hits.add(d["app_id"])
        return sorted(hits)

    def paths_to(self, library: str, version: str | None = None,
                 max_paths_per_app: int = 6) -> list[DependencyPath]:
        """Every concrete route from every application down to `library`.

        Multiple distinct paths to the same library within one app is a DIAMOND
        DEPENDENCY. The problem statement asks whether that is "redundant risk or
        compounded risk". Our answer: it is compounded REMEDIATION cost — you must fix
        every route, and fixing one parent silently leaves the other in place. So we
        return them all rather than deduplicating.
        """
        out: list[DependencyPath] = []
        for n, d in self.library_nodes():
            if d["library"] != library:
                continue
            if version and d["version"] != version:
                continue
            app_id = d["app_id"]
            root = app_node(app_id)
            if root not in self.G or not nx.has_path(self.G, root, n):
                continue

            app = self.applications.get(app_id)
            app_name = app.name if app else app_id

            count = 0
            for path in nx.all_simple_paths(self.G, root, n, cutoff=12):
                libs = [self.G.nodes[p]["library"] for p in path[1:]]
                vers = [self.G.nodes[p]["version"] for p in path[1:]]
                out.append(DependencyPath(app_id, app_name, libs, vers, len(libs)))
                count += 1
                if count >= max_paths_per_app:
                    break
        return out

    def shortest_path_to(self, app_id: str, library: str, version: str) -> DependencyPath | None:
        root = app_node(app_id)
        target = lib_node(app_id, library, version)
        if root not in self.G or target not in self.G:
            return None
        if not nx.has_path(self.G, root, target):
            return None
        path = nx.shortest_path(self.G, root, target)
        libs = [self.G.nodes[p]["library"] for p in path[1:]]
        vers = [self.G.nodes[p]["version"] for p in path[1:]]
        app = self.applications.get(app_id)
        return DependencyPath(app_id, app.name if app else app_id, libs, vers, len(libs))

    def true_depth(self, app_id: str, library: str, version: str) -> int:
        """Depth measured by TRAVERSAL, not trusted from the CSV column.

        SBOM `depth` fields are notoriously wrong — they are written by whichever build
        plugin produced the file. We recompute from the graph and use ours. This is one
        of the places a naive implementation quietly loses accuracy.
        """
        p = self.shortest_path_to(app_id, library, version)
        return p.depth if p else 1

    def diamonds(self, app_id: str | None = None) -> list[dict]:
        """Libraries reachable by MORE THAN ONE distinct path within a single app."""
        found = []
        for n, d in self.library_nodes(app_id):
            root = app_node(d["app_id"])
            if root not in self.G or not nx.has_path(self.G, root, n):
                continue
            paths = list(nx.all_simple_paths(self.G, root, n, cutoff=12))
            if len(paths) > 1:
                found.append({
                    "app_id": d["app_id"],
                    "library": d["library"],
                    "version": d["version"],
                    "path_count": len(paths),
                    "paths": [
                        " -> ".join(self.G.nodes[p]["label"] for p in path[1:])
                        for path in paths[:5]
                    ],
                })
        return found

    def version_conflicts(self) -> list[dict]:
        """The same library pinned at two different versions inside one application."""
        seen: dict[tuple[str, str], set] = defaultdict(set)
        for _, d in self.library_nodes():
            seen[(d["app_id"], d["library"])].add(d["version"])
        out = []
        for (app_id, lib), versions in seen.items():
            if len(versions) > 1:
                out.append({
                    "app_id": app_id,
                    "library": lib,
                    "versions": sorted(versions),
                })
        return out

    def blast_radius(self, library: str, version: str | None = None) -> dict:
        """If this library were compromised TODAY, what exactly is exposed?

        Answers the problem statement's Level-2 bonus: "breach impact simulation".
        We report not just which apps, but what those apps are worth: are they
        internet-facing, do they touch cardholder data, are they business critical.
        """
        apps = self.apps_using(library, version)
        detail = []
        for aid in apps:
            a = self.applications.get(aid)
            if not a:
                continue
            detail.append({
                "app_id": a.app_id,
                "app_name": a.name,
                "business_criticality": a.business_criticality,
                "internet_facing": a.internet_facing,
                "handles_pii": a.handles_pii,
                "handles_cardholder_data": a.handles_cardholder_data,
                "team": a.team,
                "owner": a.owner,
            })
        return {
            "library": library,
            "version": version,
            "affected_app_count": len(apps),
            "affected_apps": detail,
            "internet_facing_count": sum(1 for d in detail if d["internet_facing"]),
            "cardholder_data_count": sum(1 for d in detail if d["handles_cardholder_data"]),
            "pii_count": sum(1 for d in detail if d["handles_pii"]),
            "critical_app_count": sum(1 for d in detail
                                      if d["business_criticality"] == "CRITICAL"),
        }

    def descendants_of(self, app_id: str, library: str, version: str) -> list[str]:
        """Everything this library itself pulls in — its own sub-tree."""
        n = lib_node(app_id, library, version)
        if n not in self.G:
            return []
        return [self.G.nodes[d]["label"] for d in nx.descendants(self.G, n)
                if self.G.nodes[d].get("kind") == "library"]

    # ---------------------------------------------------------------------------------
    # Export for the front-end
    # ---------------------------------------------------------------------------------
    def to_cytoscape(self, app_id: str | None = None,
                     risk_by_dep: dict | None = None) -> dict:
        """Serialise (a slice of) the graph for the browser visualisation."""
        risk_by_dep = risk_by_dep or {}
        nodes, edges = [], []

        def include(n, d):
            if d.get("kind") == "application":
                return (app_id is None) or (d.get("app_id") == app_id)
            return (app_id is None) or (d.get("app_id") == app_id)

        for n, d in self.G.nodes(data=True):
            if not include(n, d):
                continue
            if d.get("kind") == "application":
                nodes.append({"data": {
                    "id": n, "label": d["label"], "kind": "application",
                    "criticality": d.get("criticality", "MEDIUM"),
                }})
            else:
                dep_id = d.get("dependency_id")
                risk = risk_by_dep.get(dep_id, {})
                nodes.append({"data": {
                    "id": n,
                    "label": d["label"],
                    "kind": "library",
                    "library": d["library"],
                    "version": d["version"],
                    "license": d.get("license", "UNKNOWN"),
                    "depth": d.get("depth", 1),
                    "dependency_id": dep_id,
                    "risk_band": risk.get("risk_band", "MINIMAL"),
                    "risk_score": risk.get("risk_score", 0),
                    "risk_type": risk.get("primary_risk", "none"),
                }})

        for u, v, d in self.G.edges(data=True):
            du, dv = self.G.nodes[u], self.G.nodes[v]
            if not include(u, du) or not include(v, dv):
                continue
            edges.append({"data": {"id": f"{u}->{v}", "source": u, "target": v}})

        return {"nodes": nodes, "edges": edges}

    def stats(self) -> dict:
        libs = [d for _, d in self.library_nodes()]
        depths = [d.get("depth", 1) for d in libs]
        return {
            "applications": len(self.applications),
            "library_nodes": len(libs),
            "edges": self.G.number_of_edges(),
            "unique_libraries": len({d["library"] for d in libs}),
            "max_depth": max(depths) if depths else 0,
            "transitive_nodes": sum(1 for d in libs if d.get("dependency_type") == "transitive"),
            "orphaned_nodes": sum(1 for d in libs if d.get("orphaned")),
        }
