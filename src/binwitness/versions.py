"""Version ordering for Maven and npm, enough to evaluate advisory ranges such as ``>= 2.0, < 2.9.10.1``."""
from __future__ import annotations

import functools
import re

_MAVEN_QUALIFIERS = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4,
                     "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}


# Upgrade advice compares every published version of a package with every bound of its advisories.
@functools.lru_cache(maxsize=1 << 16)
def maven_key(version: str) -> tuple:
    """Approximation of Maven's ComparableVersion: numbers compare numerically, known qualifiers by rank,
    unknown qualifiers after releases (as Maven does) and lexically among themselves."""
    tokens = re.findall(r"\d+|[a-zA-Z]+", version.lower())
    key = []
    for token in tokens:
        if token.isdigit():
            key.append((2, int(token), ""))
        elif token in _MAVEN_QUALIFIERS:
            key.append((1, _MAVEN_QUALIFIERS[token], ""))
        else:
            key.append((1, 8, token))
    # Trailing zeros and release markers do not change the version: 1.0 == 1.0.0 == 1.0.Final.
    while key and key[-1] in ((2, 0, ""), (1, 6, "")):
        key.pop()
    return tuple(key)


def _compare_maven(left: str, right: str) -> int:
    a, b = maven_key(left), maven_key(right)
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else None
        y = b[index] if index < len(b) else None
        if x == y:
            continue
        # A missing component equals 0 / release: "1.0" vs "1.0.1" -> less; "1.0" vs "1.0-rc1" -> greater.
        x = x if x is not None else ((2, 0, "") if y[0] == 2 else (1, 6, ""))
        y = y if y is not None else ((2, 0, "") if x[0] == 2 else (1, 6, ""))
        if x == y:
            continue
        if x[0] != y[0]:
            # Numbers rank above qualifiers at the same position (1.1 > 1-rc).
            return 1 if x[0] > y[0] else -1
        return 1 if x[1:] > y[1:] else -1
    return 0


@functools.lru_cache(maxsize=1 << 16)
def npm_key(version: str):
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?", version.strip())
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    pre_key = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else None
    # A release sorts after any of its prereleases.
    return (int(major), int(minor or 0), int(patch or 0), (1,) if pre_key is None else (0, pre_key))


def compare(ecosystem: str, left: str, right: str) -> int:
    if ecosystem.lower() == "npm":
        a, b = npm_key(left), npm_key(right)
        if a is not None and b is not None:
            return (a > b) - (a < b)
    return _compare_maven(left, right)


def in_range(ecosystem: str, version: str, expression: str) -> bool | None:
    """GitHub advisory range syntax: comma-separated ``<op> <version>`` terms, all of which must hold.
    None when the expression cannot be read."""
    terms = [t.strip() for t in expression.split(",") if t.strip()]
    if not terms:
        return None
    for term in terms:
        match = re.match(r"^(<=|>=|<|>|=)?\s*(\S+)$", term)
        if not match:
            return None
        operator, bound = match.group(1) or "=", match.group(2)
        order = compare(ecosystem, version, bound)
        if not {"<": order < 0, "<=": order <= 0, ">": order > 0, ">=": order >= 0, "=": order == 0}[operator]:
            return False
    return True


def prerelease(ecosystem: str, version: str) -> bool:
    """alpha, beta, milestone, release candidate or snapshot; npm: any prerelease tag."""
    if ecosystem.lower() == "npm":
        key = npm_key(version)
        if key is not None:
            return key[3][0] == 0
    return any(kind == 1 and 1 <= rank <= 5 for kind, rank, _ in maven_key(version))


def variant(ecosystem: str, version: str) -> str | None:
    """The suffix of a Maven version that names a build rather than a release stage: ``jre`` / ``android``
    for Guava, ``noneautotype`` for fastjson 1.2.83_noneautotype. Variants are parallel builds of one
    release, so 32.0.0-android is no upgrade for a 31.1-jre."""
    match = re.search(r"[-_]([A-Za-z]+)$", version)
    if ecosystem.lower() == "npm" or not match:
        return None
    suffix = match.group(1).lower()
    return None if suffix in _MAVEN_QUALIFIERS else suffix


def without_variant(version: str) -> str:
    return re.sub(r"[-_][A-Za-z]+$", "", version)
