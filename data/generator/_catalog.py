"""
SBOMGuard dataset generator — the static world: licenses, applications, libraries.

Split out of generate_data.py so each module stays readable.
"""
from __future__ import annotations

from datetime import date

SEED = 20260711
TODAY = date(2026, 7, 11)
UNMAINTAINED_DAYS = 730          # "no updates in 2+ years", per the problem statement

N_APPS = 10
DEPS_PER_APP = 50
N_CVES = 200

# Per-app risk composition. Chosen so that, AFTER precedence absorption
# (a dep can be both old and vulnerable — it is labelled by its worst risk),
# the global distribution lands on the spec's targets.
RISK_PLAN = {
    "vulnerable": 10,
    "license_conflict": 6,
    "unmaintained": 6,
    "transitive_vuln": 5,       # emits TWO rows each: a safe parent + a vulnerable child
    "clean": 22,                # the remainder is topped up to exactly DEPS_PER_APP
}

# =====================================================================================
# LICENSE UNIVERSE (15 licenses, per spec)
# =====================================================================================
LICENSE_RULES = [
    {"license_id": "MIT", "name": "MIT License", "category": "permissive", "copyleft": "none",
     "commercial_use": True, "distribution_safe": True, "modification_safe": True,
     "risk_level": "LOW", "risk_score": 0,
     "notes": "Maximally permissive. Compatible with proprietary distribution."},
    {"license_id": "Apache-2.0", "name": "Apache License 2.0", "category": "permissive", "copyleft": "none",
     "commercial_use": True, "distribution_safe": True, "modification_safe": True,
     "risk_level": "LOW", "risk_score": 0,
     "notes": "Permissive with an explicit patent grant. Preferred for enterprise use."},
    {"license_id": "BSD-3-Clause", "name": "BSD 3-Clause", "category": "permissive", "copyleft": "none",
     "commercial_use": True, "distribution_safe": True, "modification_safe": True,
     "risk_level": "LOW", "risk_score": 0,
     "notes": "Permissive. Requires attribution; forbids endorsement claims."},
    {"license_id": "BSD-2-Clause", "name": "BSD 2-Clause", "category": "permissive", "copyleft": "none",
     "commercial_use": True, "distribution_safe": True, "modification_safe": True,
     "risk_level": "LOW", "risk_score": 0, "notes": "Permissive. Attribution only."},
    {"license_id": "ISC", "name": "ISC License", "category": "permissive", "copyleft": "none",
     "commercial_use": True, "distribution_safe": True, "modification_safe": True,
     "risk_level": "LOW", "risk_score": 0, "notes": "Functionally equivalent to MIT."},
    {"license_id": "PSF-2.0", "name": "Python Software Foundation License", "category": "permissive",
     "copyleft": "none", "commercial_use": True, "distribution_safe": True, "modification_safe": True,
     "risk_level": "LOW", "risk_score": 0, "notes": "Permissive and GPL-compatible."},
    {"license_id": "Unlicense", "name": "The Unlicense", "category": "public-domain", "copyleft": "none",
     "commercial_use": True, "distribution_safe": True, "modification_safe": True,
     "risk_level": "LOW", "risk_score": 0, "notes": "Public-domain dedication."},

    {"license_id": "MPL-2.0", "name": "Mozilla Public License 2.0", "category": "weak-copyleft",
     "copyleft": "file", "commercial_use": True, "distribution_safe": True, "modification_safe": False,
     "risk_level": "MEDIUM", "risk_score": 4,
     "notes": "File-level copyleft. Modified MPL files must be released; linking is fine."},
    {"license_id": "LGPL-2.1", "name": "GNU Lesser GPL v2.1", "category": "weak-copyleft",
     "copyleft": "library", "commercial_use": True, "distribution_safe": True, "modification_safe": False,
     "risk_level": "MEDIUM", "risk_score": 5,
     "notes": "Safe to DYNAMICALLY LINK from proprietary code. Static linking or modification triggers copyleft."},
    {"license_id": "LGPL-3.0", "name": "GNU Lesser GPL v3.0", "category": "weak-copyleft",
     "copyleft": "library", "commercial_use": True, "distribution_safe": True, "modification_safe": False,
     "risk_level": "MEDIUM", "risk_score": 5,
     "notes": "As LGPL-2.1 plus anti-tivoisation terms. Linking OK; modification is not."},
    {"license_id": "EPL-2.0", "name": "Eclipse Public License 2.0", "category": "weak-copyleft",
     "copyleft": "file", "commercial_use": True, "distribution_safe": True, "modification_safe": False,
     "risk_level": "MEDIUM", "risk_score": 4,
     "notes": "Weak copyleft. Incompatible with GPL-2.0 in some combinations."},

    {"license_id": "GPL-2.0", "name": "GNU General Public License v2.0", "category": "strong-copyleft",
     "copyleft": "viral", "commercial_use": True, "distribution_safe": False, "modification_safe": False,
     "risk_level": "HIGH", "risk_score": 8,
     "notes": "VIRAL. Distributing a proprietary product that links GPL code forces disclosure of the whole work."},
    {"license_id": "GPL-3.0", "name": "GNU General Public License v3.0", "category": "strong-copyleft",
     "copyleft": "viral", "commercial_use": True, "distribution_safe": False, "modification_safe": False,
     "risk_level": "HIGH", "risk_score": 9,
     "notes": "VIRAL, plus patent and anti-tivoisation clauses. Highest copyleft exposure when distributed."},
    {"license_id": "AGPL-3.0", "name": "GNU Affero General Public License v3.0", "category": "network-copyleft",
     "copyleft": "viral-network", "commercial_use": True, "distribution_safe": False, "modification_safe": False,
     "risk_level": "CRITICAL", "risk_score": 10,
     "notes": "VIRAL OVER THE NETWORK. Merely SERVING the software to users triggers source disclosure. "
              "The single most dangerous license for a SaaS or banking product."},
    {"license_id": "UNKNOWN", "name": "No License Declared", "category": "unknown", "copyleft": "unknown",
     "commercial_use": False, "distribution_safe": False, "modification_safe": False,
     "risk_level": "HIGH", "risk_score": 7,
     "notes": "No license means NO RIGHTS GRANTED under copyright law. Legally you may not use it at all."},
]

LICENSE_BY_ID = {l["license_id"]: l for l in LICENSE_RULES}
PERMISSIVE = [l["license_id"] for l in LICENSE_RULES if l["category"] in ("permissive", "public-domain")]
WEAK_COPYLEFT = [l["license_id"] for l in LICENSE_RULES if l["category"] == "weak-copyleft"]
CONFLICTING = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "UNKNOWN"]

# =====================================================================================
# APPLICATIONS (10, per spec)
# The legal/criticality attributes here are what make the license engine interesting:
# the SAME GPL library is a violation in APP-001 and perfectly fine in APP-009.
# =====================================================================================
APPLICATIONS = [
    {"app_id": "APP-001", "name": "Payments-API", "team": "Payments Engineering",
     "owner": "elena.rossi@sg.com", "business_criticality": "CRITICAL", "criticality_weight": 1.5,
     "environment": "production", "internet_facing": True, "distributed": True, "proprietary": True,
     "handles_pii": True, "handles_cardholder_data": True, "ecosystem": "maven",
     "description": "Core payment authorisation and settlement service. PCI-DSS in scope."},
    {"app_id": "APP-002", "name": "CustomerPortal-Web", "team": "Digital Channels",
     "owner": "marc.dubois@sg.com", "business_criticality": "CRITICAL", "criticality_weight": 1.5,
     "environment": "production", "internet_facing": True, "distributed": True, "proprietary": True,
     "handles_pii": True, "handles_cardholder_data": False, "ecosystem": "npm",
     "description": "Public-facing retail banking web portal. GDPR in scope."},
    {"app_id": "APP-003", "name": "FraudDetection-Engine", "team": "Risk & Fraud",
     "owner": "priya.nair@sg.com", "business_criticality": "CRITICAL", "criticality_weight": 1.5,
     "environment": "production", "internet_facing": False, "distributed": False, "proprietary": True,
     "handles_pii": True, "handles_cardholder_data": True, "ecosystem": "pypi",
     "description": "Real-time transaction scoring. Internal only, but processes cardholder data."},
    {"app_id": "APP-004", "name": "TradingDesk-Gateway", "team": "Markets Technology",
     "owner": "james.okoro@sg.com", "business_criticality": "HIGH", "criticality_weight": 1.25,
     "environment": "production", "internet_facing": True, "distributed": True, "proprietary": True,
     "handles_pii": False, "handles_cardholder_data": False, "ecosystem": "maven",
     "description": "FIX protocol gateway to external trading venues."},
    {"app_id": "APP-005", "name": "MobileBanking-BFF", "team": "Mobile Engineering",
     "owner": "sofia.almeida@sg.com", "business_criticality": "HIGH", "criticality_weight": 1.25,
     "environment": "production", "internet_facing": True, "distributed": True, "proprietary": True,
     "handles_pii": True, "handles_cardholder_data": False, "ecosystem": "npm",
     "description": "Backend-for-frontend serving the iOS and Android banking apps."},
    {"app_id": "APP-006", "name": "RegReporting-Batch", "team": "Regulatory Reporting",
     "owner": "tomasz.lewandowski@sg.com", "business_criticality": "HIGH", "criticality_weight": 1.25,
     "environment": "production", "internet_facing": False, "distributed": False, "proprietary": True,
     "handles_pii": True, "handles_cardholder_data": False, "ecosystem": "pypi",
     "description": "Nightly MiFID II / EMIR regulatory submission pipeline."},
    {"app_id": "APP-007", "name": "KYC-DocumentService", "team": "Onboarding",
     "owner": "amara.diallo@sg.com", "business_criticality": "MEDIUM", "criticality_weight": 1.0,
     "environment": "production", "internet_facing": False, "distributed": False, "proprietary": True,
     "handles_pii": True, "handles_cardholder_data": False, "ecosystem": "maven",
     "description": "Identity document ingestion, OCR and verification."},
    {"app_id": "APP-008", "name": "InternalAnalytics-Dash", "team": "Data & Analytics",
     "owner": "kenji.tanaka@sg.com", "business_criticality": "MEDIUM", "criticality_weight": 1.0,
     "environment": "production", "internet_facing": False, "distributed": False, "proprietary": False,
     "handles_pii": False, "handles_cardholder_data": False, "ecosystem": "pypi",
     "description": "INTERNAL-ONLY analytics dashboard. Never distributed outside the bank."},
    {"app_id": "APP-009", "name": "DevOps-Toolchain", "team": "Platform Engineering",
     "owner": "lucas.meyer@sg.com", "business_criticality": "LOW", "criticality_weight": 0.75,
     "environment": "internal", "internet_facing": False, "distributed": False, "proprietary": False,
     "handles_pii": False, "handles_cardholder_data": False, "ecosystem": "npm",
     "description": "Internal CI/CD helper tooling. Not shipped to customers."},
    {"app_id": "APP-010", "name": "LegacyLoans-Core", "team": "Lending (Maintenance)",
     "owner": "unassigned@sg.com", "business_criticality": "HIGH", "criticality_weight": 1.25,
     "environment": "production", "internet_facing": False, "distributed": False, "proprietary": True,
     "handles_pii": True, "handles_cardholder_data": False, "ecosystem": "maven",
     "description": "Legacy loan servicing core. Maintenance mode, no active owner, highest tech debt."},
]

# =====================================================================================
# LIBRARY UNIVERSE
# =====================================================================================
MAVEN_LIBS = [
    "org.springframework:spring-core", "org.springframework:spring-web", "org.springframework:spring-beans",
    "org.springframework.boot:spring-boot-starter-web", "org.springframework.boot:spring-boot-starter-logging",
    "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api",
    "com.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson.core:jackson-core",
    "org.apache.commons:commons-text", "commons-collections:commons-collections",
    "commons-io:commons-io", "commons-codec:commons-codec", "com.google.guava:guava",
    "org.apache.httpcomponents:httpclient", "io.netty:netty-handler", "io.netty:netty-common",
    "org.hibernate:hibernate-core", "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic",
    "org.bouncycastle:bcprov-jdk15on", "org.yaml:snakeyaml", "org.postgresql:postgresql",
    "mysql:mysql-connector-java", "org.apache.tomcat:tomcat-catalina", "com.zaxxer:HikariCP",
    "org.quartz-scheduler:quartz", "org.apache.kafka:kafka-clients", "io.jsonwebtoken:jjwt",
    "org.thymeleaf:thymeleaf", "org.apache.struts:struts2-core", "xerces:xercesImpl",
    "org.dom4j:dom4j", "com.h2database:h2", "org.freemarker:freemarker",
]

NPM_LIBS = [
    "lodash", "axios", "express", "react", "react-dom", "webpack", "babel-core", "moment",
    "minimist", "node-fetch", "jsonwebtoken", "ws", "socket.io", "body-parser", "cookie-parser",
    "serialize-javascript", "handlebars", "ejs", "marked", "js-yaml", "tar", "glob-parent",
    "ansi-regex", "nth-check", "postcss", "semver-regex", "trim-newlines", "shell-quote",
    "y18n", "decode-uri-component", "async", "request", "underscore", "qs", "debug",
    "left-pad", "event-stream", "flatmap-stream", "vm2", "xmldom",
]

PYPI_LIBS = [
    "requests", "urllib3", "flask", "django", "jinja2", "werkzeug", "pyyaml", "numpy", "pandas",
    "cryptography", "pillow", "sqlalchemy", "celery", "redis", "boto3", "lxml", "beautifulsoup4",
    "paramiko", "pyjwt", "certifi", "idna", "chardet", "six", "setuptools", "pip",
    "scikit-learn", "scipy", "matplotlib", "protobuf", "grpcio", "aiohttp", "httpx",
    "tornado", "twisted", "pycrypto", "python-jose", "fastapi", "pydantic", "starlette", "click",
]

ECOSYSTEM_LIBS = {"maven": MAVEN_LIBS, "npm": NPM_LIBS, "pypi": PYPI_LIBS}
ALL_LIBS = MAVEN_LIBS + NPM_LIBS + PYPI_LIBS

ECOSYSTEM_OF = {}
for _eco, _libs in ECOSYSTEM_LIBS.items():
    for _l in _libs:
        ECOSYSTEM_OF[_l] = _eco

# Famously abandoned / bus-factor-1 packages. Drives the maintenance-risk signal.
KNOWN_ABANDONED = {
    "left-pad", "event-stream", "flatmap-stream", "request", "moment", "underscore",
    "pycrypto", "commons-collections:commons-collections", "xerces:xercesImpl",
    "org.dom4j:dom4j", "xmldom", "org.apache.struts:struts2-core", "chardet", "six",
}


# =====================================================================================
# Version helpers
# =====================================================================================
def vtuple(v: str):
    """Parse a version string into a comparable 3-tuple. Tolerant of junk suffixes."""
    parts = []
    for p in str(v).split(".")[:3]:
        num = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def bump_patch(v: str) -> str:
    a, b, c = (str(v).split(".") + ["0", "0"])[:3]
    digits = "".join(ch for ch in c if ch.isdigit()) or "0"
    return f"{a}.{b}.{int(digits) + 1}"


def make_version(rng, major_max: int = 5) -> str:
    return f"{rng.randint(0, major_max)}.{rng.randint(0, 20)}.{rng.randint(0, 12)}"
