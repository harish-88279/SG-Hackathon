"""
SBOMGuard — analyst narrative generation.

Turns a finding into the paragraph a security analyst would actually write, and a
remediation plan an engineer can actually execute.

THE HARD REQUIREMENT: THIS MUST NEVER BREAK THE DEMO
====================================================
Live LLM calls in a hackathon demo are a liability. The wifi drops, the free tier
rate-limits, the key expires, and your centrepiece dies in front of the judges.

So this module is built the other way round. The DETERMINISTIC template engine is the
default and is genuinely good — it composes a real narrative from the structured evidence
we already computed (the CVE, the exact dependency chain, the blast radius, the exploit
status, the compliance mapping). It needs no key, no network, and no luck.

The LLM is an OPTIONAL enrichment layer on top. If a key is present it rewrites the
narrative more fluently and adds judgement. If anything at all goes wrong — no key,
timeout, rate limit, malformed response — we fall back silently and the demo continues.

FREE PROVIDERS (no credit card required for any of these):
    Groq    llama-3.3-70b-versatile   ~14,400 requests/day   GROQ_API_KEY
    Gemini  gemini-2.0-flash          ~1,500 requests/day    GEMINI_API_KEY
    OpenAI  gpt-4o-mini               paid                   OPENAI_API_KEY

Set at most one. Or set none, and the offline engine handles everything.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from .. import config


# ======================================================================================
# Provider detection
# ======================================================================================
@dataclass
class Provider:
    name: str
    model: str
    available: bool
    reason: str


def detect_provider() -> Provider:
    """Pick the first available free provider. Fall back to offline."""
    pref = os.getenv("SBOMGUARD_LLM_PROVIDER", config.LLM_PROVIDER).lower()

    def _p(name):
        keys = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "openai": "OPENAI_API_KEY"}
        key = os.getenv(keys.get(name, ""), "")
        if key:
            return Provider(name, config.LLM_MODELS.get(name, ""), True,
                            f"{keys[name]} is set")
        return None

    if pref in ("groq", "gemini", "openai"):
        got = _p(pref)
        if got:
            return got
        return Provider("offline", "template-engine", False,
                        f"{pref} selected but its API key is not set")

    if pref == "offline":
        return Provider("offline", "template-engine", False, "offline mode requested")

    # auto
    for name in ("groq", "gemini", "openai"):
        got = _p(name)
        if got:
            return got

    return Provider("offline", "template-engine", False,
                    "no API key found — using the deterministic narrative engine "
                    "(no key required, works fully offline)")


# ======================================================================================
# The deterministic engine — the DEFAULT, and good enough to ship
# ======================================================================================
_SEV_LEAD = {
    "CRITICAL": "This is a five-alarm finding.",
    "HIGH": "This is a serious finding.",
    "MEDIUM": "This is a moderate finding.",
    "LOW": "This is a low-priority finding.",
}


def offline_narrative(finding, blast: dict | None = None) -> dict:
    """Compose an analyst narrative from the structured evidence, with no LLM at all."""
    dep = finding.dependency
    app = finding.application
    score = finding.score

    lead = _SEV_LEAD.get(score.severity, "This finding requires review.")
    paras: list[str] = []

    # ---- What is it, and where ----
    if score.primary_risk in ("vulnerable_dependency", "transitive_vulnerability"):
        worst = max(finding.vulns, key=lambda v: v.cvss_score)

        chain = ""
        if finding.paths:
            chain = finding.paths[0].as_chain()
        elif dep.parent_library:
            chain = f"{app.name} -> {dep.parent_library} -> {dep.library_name}@{dep.version}"
        else:
            chain = f"{app.name} -> {dep.library_name}@{dep.version}"

        if score.primary_risk == "transitive_vulnerability":
            paras.append(
                f"{lead} {app.name} is exposed to {worst.cve_id} "
                f"({worst.severity}, CVSS {worst.cvss_score}) through "
                f"{dep.library_name}@{dep.version} — a dependency nobody on the team ever "
                f"chose. It arrives {finding.true_depth} levels down the tree via "
                f"{dep.parent_library}, which is exactly why a review of direct dependencies "
                f"would never have found it. The full chain is: {chain}."
            )
        else:
            paras.append(
                f"{lead} {app.name} directly depends on {dep.library_name}@{dep.version}, "
                f"which is affected by {worst.cve_id} ({worst.severity}, CVSS "
                f"{worst.cvss_score})."
            )

        # ---- What the flaw actually does ----
        paras.append(f"{worst.summary}")

        # ---- Is it actually exploitable HERE ----
        exploit_bits = []
        if worst.known_exploited:
            exploit_bits.append(
                "This CVE is being actively exploited in the wild right now, which moves it "
                "out of the patch queue and into incident response"
            )
        if worst.exploit_maturity == "weaponised":
            exploit_bits.append("a weaponised exploit is publicly available")
        elif worst.exploit_maturity == "poc":
            exploit_bits.append("a proof-of-concept exploit exists but has not been weaponised")
        elif worst.exploit_maturity == "none":
            exploit_bits.append("no public exploit code exists yet")

        if worst.reachable:
            exploit_bits.append(
                f"and the vulnerable function ({', '.join(worst.vulnerable_functions[:1])}) "
                f"IS reachable from our code path, so the flaw is live"
            )
        else:
            exploit_bits.append(
                "however the vulnerable function is NOT reachable from any of our code paths, "
                "so the component is a liability rather than an active hole — it is a "
                "patch-next-sprint problem, not a page-someone-at-2am problem"
            )
        if exploit_bits:
            paras.append(_sentence(exploit_bits))

        # ---- Who else is holding this ----
        if blast and blast.get("affected_app_count", 0) > 1:
            n = blast["affected_app_count"]
            extras = []
            if blast.get("internet_facing_count"):
                extras.append(f"{blast['internet_facing_count']} internet-facing")
            if blast.get("cardholder_data_count"):
                extras.append(f"{blast['cardholder_data_count']} handling cardholder data")
            detail = f" ({', '.join(extras)})" if extras else ""
            paras.append(
                f"This is not an isolated problem. The same component is present in {n} "
                f"applications{detail}, so this should be handled as one coordinated "
                f"remediation campaign rather than {n} separate tickets."
            )

        # ---- Can we even fix it ----
        if worst.patch_available:
            paras.append(
                f"Remediation is straightforward: upgrade {dep.library_name} from "
                f"{dep.version} to {worst.patched_version}."
                + (f" Because the dependency is transitive, the upgrade must be applied at "
                   f"{dep.parent_library} — or pinned explicitly if the parent has not yet "
                   f"released a fixed build." if score.primary_risk == "transitive_vulnerability"
                   else "")
            )
        else:
            paras.append(
                f"There is NO upstream patch. This cannot be fixed by bumping a version "
                f"number — {dep.library_name} must be REPLACED with a maintained alternative, "
                f"which is a project, not a ticket. Until then the exposure window stays open, "
                f"so a compensating control (WAF rule, network segmentation, or disabling the "
                f"affected code path) is required now."
            )

    elif score.primary_risk == "license_conflict":
        lf = finding.license
        paras.append(
            f"{lead} {app.name} includes {dep.library_name}@{dep.version} under "
            f"{lf.license_id}. {lf.reason}"
        )
        if lf.obligation:
            paras.append(f"Required action: {lf.obligation}")
        paras.append(
            "This is legal exposure rather than a security hole, but for a regulated bank it "
            "is not the lesser problem — copyleft violations are enforceable, and the remedy "
            "a court can order is publication of the source code of the product."
        )

    elif score.primary_risk == "unmaintained":
        mf = finding.maintenance
        paras.append(
            f"{lead} {dep.library_name}@{dep.version} in {app.name} has had no release in "
            f"{mf.years} years and has {mf.maintainer_count} maintainer(s). {mf.reason}"
        )
        paras.append(
            "There is no vulnerability here today. The risk is structural: when a CVE is "
            "eventually published against this component — and for a package this old, it "
            "will be — there will be no maintainer to ship a fix, and 'upgrade' will not be "
            "an available option. The time to replace an abandoned dependency is before it "
            "becomes an emergency, not during one."
        )

    else:
        paras.append("No risk identified for this component.")

    # ---- Compliance ----
    comp = _compliance_sentence(score.primary_risk)
    if comp:
        paras.append(comp)

    return {
        "narrative": "\n\n".join(paras),
        "generated_by": "deterministic-template-engine",
        "model": "none (no API key required)",
    }


def _sentence(bits: list[str]) -> str:
    if not bits:
        return ""
    text = bits[0]
    for b in bits[1:]:
        text += (" " if b.startswith(("and", "however", "but")) else ", ") + b
    return text.rstrip(",") + "."


def _compliance_sentence(risk_type: str) -> str:
    entries = config.COMPLIANCE_MAP.get(risk_type, [])
    if not entries:
        return ""
    refs = ", ".join(f"{fw} {ctrl}" for fw, ctrl, _ in entries)
    return f"For the audit trail, this finding maps to {refs}."


# ======================================================================================
# LLM enrichment (optional)
# ======================================================================================
SYSTEM_PROMPT = """You are a senior application-security analyst at a European \
investment bank, writing for an engineering team that will act on what you say today.

Rules:
- Lead with the consequence, not the CVE number.
- Be concrete and specific. Name the exact library, version, chain and fix.
- If the vulnerable function is not reachable, SAY SO plainly and de-escalate. Do not
  cry wolf; it is how security teams lose credibility.
- If there is no patch, say that upgrading is impossible and a replacement is required.
- No bullet points. No headings. Three short paragraphs at most.
- Never invent a CVE, a version number or a fact that is not in the evidence given.
"""


def _build_prompt(finding, blast: dict | None) -> str:
    dep, app, score = finding.dependency, finding.application, finding.score
    ev = {
        "application": {
            "name": app.name,
            "business_criticality": app.business_criticality,
            "internet_facing": app.internet_facing,
            "handles_cardholder_data": app.handles_cardholder_data,
            "handles_pii": app.handles_pii,
        },
        "component": {
            "library": dep.library_name,
            "version": dep.version,
            "license": dep.license,
            "dependency_type": dep.dependency_type,
            "depth": finding.true_depth,
            "parent": dep.parent_library or None,
            "chain": finding.paths[0].as_chain() if finding.paths else None,
        },
        "risk": {
            "primary_risk": score.primary_risk,
            "severity": score.severity,
            "risk_score": round(score.risk_score, 1),
            "priority_score": round(score.priority_score, 1),
            "drivers": score.drivers,
        },
        "vulnerabilities": [
            {
                "cve": v.cve_id, "cvss": v.cvss_score, "severity": v.severity,
                "summary": v.summary, "patch_available": v.patch_available,
                "patched_version": v.patched_version,
                "exploit_maturity": v.exploit_maturity,
                "known_exploited": v.known_exploited,
                "vulnerable_function_reachable_from_our_code": v.reachable,
            } for v in finding.vulns[:3]
        ],
        "license_finding": finding.license.to_dict() if finding.license else None,
        "blast_radius": blast,
    }
    return (
        "Write the analyst narrative for this finding. Use ONLY the evidence below.\n\n"
        + json.dumps(ev, indent=2, default=str)
    )


def _call_groq(prompt: str, model: str, timeout: int = 20) -> str:
    key = os.environ["GROQ_API_KEY"]
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 600,
    }).encode()
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return data["choices"][0]["message"]["content"].strip()


def _call_gemini(prompt: str, model: str, timeout: int = 20) -> str:
    key = os.environ["GEMINI_API_KEY"]
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={key}")
    body = json.dumps({
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 600},
    }).encode()
    req = urllib.request.Request(url, data=body,
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return data["candidates"][0]["content"]["parts"][0]["text"].strip()


def _call_openai(prompt: str, model: str, timeout: int = 20) -> str:
    key = os.environ["OPENAI_API_KEY"]
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 600,
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return data["choices"][0]["message"]["content"].strip()


_DISPATCH = {"groq": _call_groq, "gemini": _call_gemini, "openai": _call_openai}


def generate(finding, blast: dict | None = None, force_offline: bool = False) -> dict:
    """Produce a narrative. NEVER raises — always returns something usable."""
    if force_offline:
        return offline_narrative(finding, blast)

    provider = detect_provider()
    if not provider.available:
        out = offline_narrative(finding, blast)
        out["provider_note"] = provider.reason
        return out

    try:
        fn = _DISPATCH[provider.name]
        text = fn(_build_prompt(finding, blast), provider.model)
        if not text or len(text) < 40:
            raise ValueError("LLM returned an empty or unusably short narrative")
        return {
            "narrative": text,
            "generated_by": f"llm:{provider.name}",
            "model": provider.model,
        }
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError,
            ValueError, TimeoutError, OSError) as exc:
        # The demo must not die because a free tier rate-limited us.
        out = offline_narrative(finding, blast)
        out["provider_note"] = (
            f"{provider.name} call failed ({type(exc).__name__}); fell back to the "
            f"deterministic engine. The narrative below is still fully evidence-based."
        )
        return out
