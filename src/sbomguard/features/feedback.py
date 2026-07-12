"""
SBOMGuard — the false-positive feedback loop (Level-2 bonus).

WHY A FEEDBACK LOOP IS THE FEATURE THAT DECIDES ADOPTION
========================================================
A security tool's real failure mode is not missing a vulnerability. It is being switched
off. And it gets switched off when an engineer marks something a false positive, and then
sees the SAME finding again next week, and the week after.

At that point the tool has told the engineer, clearly, that their judgement does not
matter. They stop reading it. Recall becomes irrelevant, because nobody is looking.

So suppressions here are DURABLE and STRUCTURED. Marking a finding false-positive:

    1. persists to disk, so the next scan honours it
    2. records WHO, WHEN and WHY — an auditor will ask, and "someone dismissed it" is
       not an answer
    3. can carry an EXPIRY, because "this build is patched" is true until the next release
    4. generalises: a suppression can apply to one dependency, or to a whole
       (library, version, CVE) triple across the estate — so you do not dismiss the same
       thing ten times
    5. is REPORTED. A suppression is not a deletion. Suppressed findings appear in the
       compliance evidence with their justification, so the tool never silently hides risk.

That last point matters most. There is a real difference between a tool that lets you
suppress findings and a tool that lets you hide them. This is the former.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, asdict, field
from datetime import date, datetime, timedelta
from pathlib import Path

from .. import config


STORE = config.ARTIFACT_DIR / "suppressions.json"

VALID_REASONS = {
    "PATCHED_IN_BUILD": "The shipped build carries a backported fix.",
    "NOT_REACHABLE": "The vulnerable code path is not reachable from our application.",
    "COMPENSATING_CONTROL": "A compensating control (WAF, segmentation) blocks exploitation.",
    "NOT_DISTRIBUTED": "The application is not distributed, so copyleft is not triggered.",
    "LEGAL_APPROVED": "Counsel has reviewed and accepted this license.",
    "RISK_ACCEPTED": "The risk has been formally accepted by the application owner.",
    "FALSE_MATCH": "The version-range match is wrong; this build is not affected.",
}


@dataclass
class Suppression:
    suppression_id: str
    scope: str                      # dependency | library_version | library_cve | cve
    target: str                     # the key the scope applies to
    reason_code: str
    justification: str
    created_by: str
    created_at: str
    expires_at: str | None = None
    app_id: str | None = None
    cve_id: str | None = None
    active: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["expired"] = self.is_expired()
        return d

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            return date.fromisoformat(self.expires_at) < config.TODAY
        except ValueError:
            return False

    def applies_to(self, finding) -> bool:
        if not self.active or self.is_expired():
            return False

        dep = finding.dependency
        if self.app_id and dep.app_id != self.app_id:
            return False

        if self.scope == "dependency":
            return dep.dependency_id == self.target

        if self.scope == "library_version":
            return f"{dep.library_name}@{dep.version}" == self.target

        if self.scope == "library_cve":
            lib, _, cve = self.target.partition("|")
            return (dep.library_name == lib
                    and any(v.cve_id == cve for v in finding.vulns))

        if self.scope == "cve":
            return any(v.cve_id == self.target for v in finding.vulns)

        return False


class FeedbackStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or STORE)
        self.suppressions: list[Suppression] = []
        self.load()

    # ---------------------------------------------------------------------------------
    def load(self) -> None:
        if not self.path.exists():
            self.suppressions = []
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self.suppressions = []
            return
        self.suppressions = [Suppression(**r) for r in raw]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([asdict(s) for s in self.suppressions], indent=2),
            encoding="utf-8",
        )

    # ---------------------------------------------------------------------------------
    def add(self, scope: str, target: str, reason_code: str, justification: str,
            created_by: str, expires_in_days: int | None = None,
            app_id: str | None = None, cve_id: str | None = None) -> Suppression:
        if reason_code not in VALID_REASONS:
            raise ValueError(
                f"Unknown reason_code '{reason_code}'. A suppression must state WHY. "
                f"Valid: {', '.join(VALID_REASONS)}"
            )
        if not justification or len(justification.strip()) < 10:
            raise ValueError(
                "A justification of at least 10 characters is required. 'not a problem' is "
                "not an audit trail."
            )

        expires = None
        if expires_in_days:
            expires = (config.TODAY + timedelta(days=expires_in_days)).isoformat()

        s = Suppression(
            suppression_id=f"SUP-{uuid.uuid4().hex[:8].upper()}",
            scope=scope, target=target, reason_code=reason_code,
            justification=justification.strip(), created_by=created_by,
            created_at=datetime.now().isoformat(timespec="seconds"),
            expires_at=expires, app_id=app_id, cve_id=cve_id,
        )
        self.suppressions.append(s)
        self.save()
        return s

    def revoke(self, suppression_id: str) -> bool:
        for s in self.suppressions:
            if s.suppression_id == suppression_id:
                s.active = False
                self.save()
                return True
        return False

    # ---------------------------------------------------------------------------------
    def apply(self, result) -> dict:
        """Apply suppressions to an analysis. Returns what changed and WHY.

        Note carefully: this does NOT delete findings. It reclassifies them as suppressed
        and reports them separately, with their justification. A tool that lets you hide
        risk is a liability; a tool that lets you DOCUMENT accepted risk is a control.
        """
        active = [s for s in self.suppressions if s.active and not s.is_expired()]
        expired = [s for s in self.suppressions if s.is_expired() and s.active]

        suppressed = []
        for f in result.findings:
            if not f.score.at_risk:
                continue
            for s in active:
                if s.applies_to(f):
                    suppressed.append({
                        "dependency_id": f.dependency.dependency_id,
                        "app_name": f.application.name,
                        "library": f.dependency.library_name,
                        "version": f.dependency.version,
                        "original_risk": f.score.primary_risk,
                        "original_severity": f.score.severity,
                        "original_priority": round(f.score.priority_score, 1),
                        "suppression_id": s.suppression_id,
                        "reason_code": s.reason_code,
                        "reason": VALID_REASONS[s.reason_code],
                        "justification": s.justification,
                        "suppressed_by": s.created_by,
                        "expires_at": s.expires_at,
                    })
                    f.score.at_risk = False
                    f.score.priority_score = 0.0
                    f.score.risk_band = "SUPPRESSED"
                    break

        return {
            "active_suppressions": len(active),
            "expired_suppressions": [s.to_dict() for s in expired],
            "expired_count": len(expired),
            "findings_suppressed": len(suppressed),
            "suppressed": suppressed,
            "warning": (
                f"{len(expired)} suppression(s) have EXPIRED and are no longer being applied. "
                f"Their findings are live again. This is deliberate: 'the build is patched' "
                f"is true until the next release, and a suppression that never expires is a "
                f"permanent blind spot."
            ) if expired else None,
        }

    def stats(self) -> dict:
        active = [s for s in self.suppressions if s.active and not s.is_expired()]
        by_reason = {}
        for s in active:
            by_reason[s.reason_code] = by_reason.get(s.reason_code, 0) + 1
        return {
            "total": len(self.suppressions),
            "active": len(active),
            "expired": sum(1 for s in self.suppressions if s.is_expired()),
            "revoked": sum(1 for s in self.suppressions if not s.active),
            "by_reason": by_reason,
            "valid_reason_codes": VALID_REASONS,
        }
