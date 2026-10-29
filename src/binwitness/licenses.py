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
    ("Public Domain", r"public domain|\bcc0\b"),
    ("Unlicense", r"\bunlicense\b"),
    ("ISC", r"\bisc\b"),
    ("Zlib", r"\bzlib\b"),
    ("BSL-1.0", r"boost software licen[cs]e|\bbsl-1\.0\b"),
    ("Python-2.0", r"python software foundation licen[cs]e|\bpython-2\.0\b|\bpsf\b"),
    ("BlueOak-1.0.0", r"blue ?oak"),
    ("CC-BY", r"\bcc-by\b(?!-)|creative commons attribution(?!-)"),
    ("WTFPL", r"\bwtfpl\b"),
    ("Mulan PSL", r"mulan"),
]

FAMILIES = ("source-available", "strong-copyleft", "copyleft-with-exception", "weak-copyleft", "permissive")
UNKNOWN = "unknown"
_RANK_PREFIX = {"SSPL": 1, "BUSL": 0, "Elastic": 0, "AGPL": 1, "GPL": 1, "LGPL": 3, "EPL": 3, "MPL": 3,
                "CDDL": 3, "CC-BY-SA": 3, "Artistic": 3, "OFL": 3}
_PERMISSIVE = {"Apache-2.0", "Apache", "EDL", "MIT", "0BSD", "BSD", "Bouncy Castle", "Public Domain", "Unlicense",
               "ISC", "Zlib", "BSL-1.0", "Python-2.0", "BlueOak-1.0.0", "CC-BY", "WTFPL", "Mulan PSL"}


def detect(text: str, first_only: bool = False) -> list[str]:
    low = re.sub(r"\s+", " ", text.lower())
    hits = []
    for name, pattern in PATTERNS:
        match = re.search(pattern, low)
        if match:
            hits.append((match.start(), name))
    if not hits:
        return []
    names = [min(hits)[1]] if first_only else [n for _, n in sorted(hits)]
    if "Apache-2.0" in names and "Apache" in names:
        names.remove("Apache")
    if "CC-BY-SA" in names and "CC-BY" in names:
        names.remove("CC-BY")
    out = []
    for name in names:
        if name == "GPL":
            # Read the version only next to the GPL mention: full LICENSE files append third-party notices
            # whose "version 3" has nothing to do with this component.
            at = next(pos for pos, hit in hits if hit == "GPL")
            near = low[max(0, at - 200):at + 300]
            version = ("3.0" if re.search(r"version 3|v3\b|gpl-?3|gplv3", near)
                       else "2.0" if re.search(r"version 2|v2\b|gpl-?2|gplv2", near) else "")
            name = f"GPL-{version}" if version else "GPL"
            if re.search(r"classpath|\bcpe\b", low):
                name += "-with-classpath-exception"
            elif "foss exception" in low or "foss-exception" in low:
                name += "-with-FOSS-exception"
        out.append(name)
    return list(dict.fromkeys(out))


def rank(name: str) -> int | None:
    """Lower is more restrictive; None when unrecognised."""
    if name.startswith("GPL") and "classpath" in name:
        return 2
    for prefix, value in _RANK_PREFIX.items():
        if name.startswith(prefix):
            return value
    return 4 if name in _PERMISSIVE else None


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
