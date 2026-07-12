"""
SBOMGuard — the bonus feature set (Levels 1-3 of the problem statement).

    remediation.py   an ordered, executable playbook — not a list of findings
    correlation.py   multi-application correlation: one fix, many apps
    compliance.py    per-application compliance gap analysis + audit evidence
    feedback.py      false-positive feedback loop that actually changes future scans
    policy_gate.py   a CI/CD gate that can fail a build — the tool with teeth
"""

__all__ = ["remediation", "correlation", "compliance", "feedback", "policy_gate"]
