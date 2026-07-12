"""
SBOMGuard — Software Supply Chain Risk Scorer.

Société Générale hackathon, PB-10.

A dependency-graph-based SBOM analyser that answers, in one second, the question that
took the industry four days to answer in December 2021:

    "Which of our applications are affected by this CVE — including through
     transitive dependencies nobody knew we had?"
"""

__version__ = "1.0.0"
__all__ = ["analyzer", "graph", "detectors", "scoring", "ingest", "versions", "config"]
