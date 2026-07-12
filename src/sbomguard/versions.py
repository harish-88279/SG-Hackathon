"""
SBOMGuard — version range matching.

This is the least glamorous module in the project and the one most likely to be the
difference between a working scanner and a broken one. Every false positive and false
negative in vulnerability detection ultimately comes down to comparing two version
strings correctly.

The naive approach — string equality against a list of "affected versions" — fails
immediately on real data:

    "is 2.14.1 affected by a CVE whose range is [2.0.0, 2.15.0)?"

String comparison says "2.14.1" > "2.15.0" because '4' > '1' lexicographically. That
single bug would make us miss Log4Shell.

We therefore parse versions into comparable tuples and evaluate half-open intervals
[introduced, fixed) — the same semantics OSV and the NVD actually use.
"""
from __future__ import annotations

import re
from functools import total_ordering

# Matches: 1.2.3 | 1.2 | 1 | 2.14.1-rc1 | 4.17.21+build5 | 1.0.0.RELEASE
_VERSION_RE = re.compile(
    r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.\-+_](.*))?\s*$"
)

# Pre-release identifiers rank BELOW the release they precede: 2.0.0-rc1 < 2.0.0
_PRERELEASE_TOKENS = ("alpha", "beta", "rc", "pre", "dev", "snapshot", "m", "cr")


@total_ordering
class Version:
    """A tolerant, comparable version.

    Deliberately NOT strict semver: real SBOMs are full of things like `1.0.0.RELEASE`,
    `2.14.1-jre`, `4.17.21+ds`, and `0.9`. A scanner that throws on those is useless.
    Anything we cannot parse degrades to (0, 0, 0) and is reported, never silently dropped.
    """

    __slots__ = ("raw", "release", "prerelease", "parsed")

    def __init__(self, raw: str):
        self.raw = str(raw or "").strip()
        m = _VERSION_RE.match(self.raw)
        if not m:
            self.release = (0, 0, 0)
            self.prerelease = None
            self.parsed = False
            return

        major = int(m.group(1))
        minor = int(m.group(2) or 0)
        patch = int(m.group(3) or 0)
        suffix = (m.group(4) or "").lower()

        self.release = (major, minor, patch)
        self.parsed = True
        # Only treat the suffix as a pre-release if it actually looks like one.
        # `2.14.1-jre` is NOT a pre-release; `2.0.0-rc1` is.
        self.prerelease = suffix if any(t in suffix for t in _PRERELEASE_TOKENS) else None

    # -- ordering -------------------------------------------------------------------
    def _key(self):
        # A pre-release sorts before the corresponding release.
        return (self.release, 0 if self.prerelease else 1, self.prerelease or "")

    def __eq__(self, other):
        if not isinstance(other, Version):
            other = Version(other)
        return self._key() == other._key()

    def __lt__(self, other):
        if not isinstance(other, Version):
            other = Version(other)
        return self._key() < other._key()

    def __repr__(self):
        return f"Version({self.raw!r})"

    def __hash__(self):
        return hash(self._key())


def parse(v) -> Version:
    return v if isinstance(v, Version) else Version(v)


def in_range(version, introduced=None, fixed=None) -> bool:
    """Evaluate the half-open interval [introduced, fixed).

    This is exactly the OSV / NVD convention:
      * `introduced` is INCLUSIVE  — the first version that carries the flaw
      * `fixed`      is EXCLUSIVE  — the first version that does NOT carry it

    `fixed is None` means NO FIX HAS EVER SHIPPED. Everything from `introduced` onward is
    affected, forever. That case matters: it is the difference between "upgrade this" and
    "you must replace this library entirely", and it changes the remediation plan.
    """
    v = parse(version)
    lo = parse(introduced) if introduced not in (None, "") else Version("0.0.0")
    if v < lo:
        return False
    if fixed in (None, ""):
        return True                       # unpatchable: affected in perpetuity
    return v < parse(fixed)


def is_affected(version, affected_spec: dict) -> bool:
    """Convenience wrapper around a `{"introduced": ..., "fixed": ...}` block."""
    if not affected_spec:
        return False
    return in_range(version,
                    affected_spec.get("introduced"),
                    affected_spec.get("fixed"))


def satisfies_any(version, specs) -> bool:
    return any(is_affected(version, s) for s in (specs or []))


def compare(a, b) -> int:
    va, vb = parse(a), parse(b)
    if va < vb:
        return -1
    if vb < va:
        return 1
    return 0


def max_version(versions):
    vs = [parse(v) for v in versions if v not in (None, "")]
    return max(vs).raw if vs else None


def is_upgrade(current, target) -> bool:
    """True if `target` is strictly newer than `current` — i.e. the fix is a real upgrade."""
    return compare(current, target) < 0
