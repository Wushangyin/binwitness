"""License recognition from free text, POM declarations and SPDX expressions, and family classification."""
from __future__ import annotations

import re

# (name, pattern). Declarations may list several (dual licensing), so all hits are kept; a LICENSE text only
# yields the first hit, because its title comes first and the body often mentions others (LGPL cites GPL).
PATTERNS = [
    ("SSPL-1.0", r"server side public licen[cs]e|\bsspl\b"),
    ("BUSL-1.1", r"business source licen[cs]e|\bbusl\b"),
    ("Elastic-2.0", r"elastic licen[cs]e|\belastic-2\.0\b"),
    ("AGPL-3.0", r"affero|\bagpl"),
    ("LGPL", r"lesser general public|library general public|\blgpl|/lgpl"),
    ("GPL", r"(?<!lesser )(?<!library )(?<!affero )general public licen[cs]e|(?<![al])\bgpl"),
    ("Apache-2.0", r"apache licen[cs]e,? (version )?2|apache[- ]2\.0|apache software licen[cs]e.{0,20}2\.0"
                   r"|licenses/license-2\.0|\bal 2\.0|\basl 2\.0"),
    ("Apache", r"apache licen[cs]e|apache software licen[cs]e"),
    ("EPL", r"eclipse public licen[cs]e|\bepl\b|/epl-"),
    ("EDL", r"eclipse distribution licen[cs]e|\bedl\b|/edl-"),
    ("MPL", r"mozilla public licen[cs]e|\bmpl\b|/mpl-"),
    ("CDDL", r"common development and distribution|\bcddl\b"),
    ("CC-BY-SA", r"\bcc-by-sa\b|creative commons attribution-sharealike"),
    ("Artistic-2.0", r"artistic licen[cs]e|\bartistic-"),
    ("OFL-1.1", r"open font licen[cs]e|\bofl\b"),
    ("MIT", r"\bmit licen[cs]e|\bmit\b|permission is hereby granted, free of charge|licenses/mit"),
    ("0BSD", r"\b0bsd\b"),
    ("BSD", r"\bbsd\b|redistribution and use in source and binary forms|licenses/bsd"),
    ("Bouncy Castle", r"bouncy castle licen[cs]e"),
    ("CC0-1.0", r"\bcc0\b|creative commons zero"),
    ("Public Domain", r"public domain"),
    ("Unlicense", r"\bunlicense\b"),
    ("ISC", r"\bisc\b"),
    ("Zlib", r"\bzlib\b"),
    ("BSL-1.0", r"boost software licen[cs]e|\bbsl-1\.0\b"),
    ("Python-2.0", r"python software foundation licen[cs]e|\bpython-2\.0\b|\bpsf\b"),
    ("BlueOak-1.0.0", r"blue ?oak"),
    # CC-BY-4.0, but not the NonCommercial or NoDerivatives variants (CC-BY-NC-4.0), which are not open licenses.
    ("CC-BY", r"\bcc-by(?=-\d|\b(?!-))|creative commons attribution(?!-)"),
    ("WTFPL", r"\bwtfpl\b"),
    ("Mulan PSL", r"mulan"),
]
# A version written right after the name: "EPL - v 1.0", "epl-v10", "LGPL, version 2.1", "MPL 2.0".
_VERSION_AFTER = re.compile(r"[\s,:(-]*(?:licen[cs]e)?(?:\s*\([a-z0-9. -]+\))?[\s,:(-]*(?:v|version)?[\s.]*"
                            r"(\d+)(?:\.(\d+))?")
_VERSIONS = {"Apache": ("1.0", "1.1", "2.0"), "EPL": ("1.0", "2.0"), "EDL": ("1.0",), "MPL": ("1.0", "1.1", "2.0"),
             "LGPL": ("2.0", "2.1", "3.0"), "CDDL": ("1.0", "1.1"), "CC-BY": ("3.0", "4.0"),
             "CC-BY-SA": ("3.0", "4.0"), "Mulan PSL": ("1", "2")}
_BSD_CLAUSES = [("BSD-3-Clause", r"bsd[- ]3[- ]clause|3-clause|three-clause|(new|revised|modified) bsd|"
                                 r"neither the name"),
                ("BSD-2-Clause", r"bsd[- ]2[- ]clause|2-clause|two-clause|simplified bsd|freebsd")]
# The names :func:`detect` gives that are SPDX license ids, as CycloneDX 1.5 lists them (some are deprecated
# there, kept because the text does not say which variant it is: GPL-2.0 does not tell "only" from "or later").
SPDX_IDS = {"Apache-1.0", "Apache-1.1", "Apache-2.0", "MIT", "0BSD", "ISC", "Zlib", "BSL-1.0", "Python-2.0",
            "BlueOak-1.0.0", "Unlicense", "WTFPL", "SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "Artistic-2.0", "OFL-1.1",
            "AGPL-3.0", "GPL-2.0", "GPL-3.0", "GPL-2.0-with-classpath-exception", "LGPL-2.0", "LGPL-2.1",
            "LGPL-3.0", "EPL-1.0", "EPL-2.0", "MPL-1.0", "MPL-1.1", "MPL-2.0", "CDDL-1.0", "CDDL-1.1",
            "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "CC-BY-3.0", "CC-BY-4.0", "CC-BY-SA-3.0", "CC-BY-SA-4.0",
            "MulanPSL-1.0", "MulanPSL-2.0"}
# The Eclipse Distribution License 1.0 is the BSD 3-clause text, which is how SPDX lists it.
_SPDX_ALIAS = {"EDL-1.0": "BSD-3-Clause", "EDL": "BSD-3-Clause"}

FAMILIES = ("source-available", "strong-copyleft", "copyleft-with-exception", "weak-copyleft", "permissive")
UNKNOWN = "unknown"
_RANK_PREFIX = {"SSPL": 1, "BUSL": 0, "Elastic": 0, "AGPL": 1, "GPL": 1, "LGPL": 3, "EPL": 3, "MPL": 3,
                "CDDL": 3, "CC-BY-SA": 3, "Artistic": 3, "OFL": 3}
_PERMISSIVE = ("Apache", "EDL", "MIT", "0BSD", "BSD", "Bouncy Castle", "Public Domain", "Unlicense", "ISC", "Zlib",
               "BSL-1.0", "Python-2.0", "BlueOak-1.0.0", "CC-BY", "CC0-1.0", "WTFPL", "Mulan PSL", "MulanPSL")


def detect(text: str, first_only: bool = False) -> list[str]:
    low = re.sub(r"\s+", " ", text.lower())
    hits = []
    for name, pattern in PATTERNS:
        match = re.search(pattern, low)
        if match:
            hits.append((match.start(), -len(name), name, match.end()))
    if not hits:
        return []
    # Where two names match at the same place ("apache license, version 2" is both Apache and Apache-2.0),
    # the longer one is the more specific.
    hits.sort()
    chosen = hits[:1] if first_only else hits
    if "CC-BY-SA" in [h[2] for h in chosen]:
        chosen = [h for h in chosen if h[2] != "CC-BY"]
    out = []
    for at, _, name, end in chosen:
        if name in _VERSIONS:
            name = _with_version(name, low[end:end + 60])
        elif name == "BSD":
            name = next((clause for clause, pattern in _BSD_CLAUSES
                         if re.search(pattern, low[max(0, at - 20):end + 40] if not first_only else low)),
                        "BSD")
        elif name == "GPL":
            # Read the version only next to the GPL mention: full LICENSE files append third-party notices
            # whose "version 3" has nothing to do with this component.
            near = low[max(0, at - 200):at + 300]
            version = ("3.0" if re.search(r"version 3|v3\b|gpl-?3|gplv3", near)
                       else "2.0" if re.search(r"version 2|v2\b|gpl-?2|gplv2", near) else "")
            name = f"GPL-{version}" if version else "GPL"
            if re.search(r"classpath|\bcpe\b", low):
                name += "-with-classpath-exception"
            elif "foss exception" in low or "foss-exception" in low:
                name += "-with-FOSS-exception"
        out.append(name)
    # "Apache License" next to "Apache License, Version 2.0" in one declaration says nothing more.
    out = [n for n in out if not any(o != n and o.startswith(n + "-") and not o.startswith(("CC-BY-SA", "GPL-"))
                                     for o in out)]
    return list(dict.fromkeys(out))


def _with_version(name: str, after: str) -> str:
    if name == "Mulan PSL":
        # "Mulan Permissive Software License，Version 2" (a full-width comma), or "MulanPSL2" in its URL.
        match = re.match(r"\s*(?:permissive software licen[cs]e|psl)[\s,，:-]*(?:v|version)?\s*(\d)", after)
        return f"MulanPSL-{match.group(1)}.0" if match and match.group(1) in _VERSIONS[name] else name
    match = _VERSION_AFTER.match(after)
    if not match:
        return name
    major, minor = match.groups()
    if minor is None and len(major) == 2:
        major, minor = major[0], major[1]   # epl-v10, lgpl21
    version = f"{major}.{minor or 0}"
    return f"{name}-{version}" if version in _VERSIONS[name] else name


def spdx_id(name: str) -> str | None:
    """The SPDX id of a name :func:`detect` gives, or None when it has none (an unversioned "BSD")."""
    name = _SPDX_ALIAS.get(name, name)
    return name if name in SPDX_IDS else None


def rank(name: str) -> int | None:
    """Lower is more restrictive; None when unrecognised."""
    if name.startswith("GPL") and "classpath" in name:
        return 2
    for prefix, value in _RANK_PREFIX.items():
        if name.startswith(prefix):
            return value
    return 4 if any(name == p or name.startswith(p + "-") for p in _PERMISSIVE) else None


def family(names: list[str], conjunctive: bool = False) -> str:
    """Licenses listed side by side are alternatives (take the most permissive); conjunctive ones all apply."""
    ranks = [rank(n) for n in names]
    known = [r for r in ranks if r is not None]
    if not known or (conjunctive and len(known) != len(ranks)):
        return UNKNOWN
    return FAMILIES[min(known) if conjunctive else max(known)]


def expression_family(expression: str) -> str:
    """Family of an SPDX expression: OR picks the most permissive branch, AND the most restrictive."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expression)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        position += 1
        return tokens[position - 1]

    def either():
        ranks = [both()]
        while peek() and peek().upper() == "OR":
            take()
            ranks.append(both())
        known = [r for r in ranks if r is not None]
        return max(known) if known else None

    def both():
        ranks = [atom()]
        while peek() and peek().upper() == "AND":
            take()
            ranks.append(atom())
        return None if None in ranks else min(ranks)

    def atom():
        token = take() if peek() else ""
        if token == "(":
            value = either()
            if peek() == ")":
                take()
            return value
        if peek() and peek().upper() == "WITH":
            take()
            token = f"{token} with {take() if peek() else ''}"
        names = detect(token)
        known = [r for r in map(rank, names) if r is not None]
        return min(known) if known else None

    try:
        value = either()
    except IndexError:
        value = None
    return UNKNOWN if value is None else FAMILIES[value]


def pom_licenses(pom: str) -> list[str]:
    block = re.search(r"<licenses>(.*?)</licenses>", re.sub(r"<!--.*?-->", "", pom, flags=re.S), re.S)
    if not block:
        return []
    return detect(" ; ".join(re.findall(r"<(?:name|url)>\s*([^<]+?)\s*</(?:name|url)>", block.group(1))))


def manifest_value(raw: bytes, key: str) -> str:
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n").replace("\n ", "")
    match = re.search(rf"^{re.escape(key)}:\s*(.+)$", text, re.M)
    return match.group(1).strip() if match else ""
