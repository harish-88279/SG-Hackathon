"""
SBOMGuard — the intelligence layer (Option A of the problem statement).

Four capabilities, each of which must EARN its place. Adding machine learning to a problem
that a rule already solves perfectly is not sophistication, it is decoration — so each
module below states plainly what it adds over the deterministic core, and where it does
not add anything, we say so.

    classifier.py    an ML risk classifier trained on the labels. Honest finding: the
                     rules already score 100%, so the classifier's real value is as an
                     INDEPENDENT SECOND OPINION that generalises to libraries and CVEs
                     absent from our database.

    clustering.py    unsupervised grouping of dependencies into "risk archetypes", which
                     turns 265 individual findings into ~6 remediation campaigns.

    narrative.py     LLM-generated analyst narratives. Free-tier (Groq/Gemini) with a
                     deterministic offline fallback, so the demo NEVER depends on a key.

    osv_client.py    live enrichment from OSV.dev — free, no API key, no rate limit.
"""

__all__ = ["classifier", "clustering", "narrative", "osv_client"]
