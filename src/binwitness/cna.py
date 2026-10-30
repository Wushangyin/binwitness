"""Candidates from the CVE records as their CNAs published them (the cvelistV5 repository of the CVE Program).

NVD gives a record its CPEs days to months after the CNA (the organisation that assigned the CVE) published it;
in between, the CNA's own record is all there is. It names the product by vendor and product name, sometimes
by a Maven package or repository URL, and states which versions are affected in the CVE JSON 5 terms.

A record reaches a package by the package it names (path A), by a CPE it carries that is linked with the
package (B, through the links learned from NVD), or by its product name, learned the way the CPE links are:
from the CVEs OSV attributes to a package, whose CNA records mostly name the same product (C).
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from binwitness import fixes, nvd
from binwitness.versions import compare, in_range

CVELIST = "https://github.com/CVEProject/cvelistV5"
RELEASES_FEED = f"{CVELIST}/releases.atom"
RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
TAG = re.compile(r"releases/tag/(cve_(\d{4}-\d{2}-\d{2})_(\d{4})Z)")
# Product names that name nothing.
PLACEHOLDERS = {"", "n/a", "na", "unspecified", "unknown", "-", "*", "all", "all versions", "none"}
VERSIONISH = re.compile(r"^[vV]?\d[\w.+-]*$")
OPERATOR = re.compile(r"^\s*(<=|>=|<|>|=)")
# Words a vendor name carries that say nothing about who it is: "The Eclipse Foundation" is eclipse.
STOP_WORDS = {"the", "inc", "llc", "ltd", "co", "corp", "corporation", "foundation", "software", "project", "org",
              "gmbh", "limited", "technologies", "technology", "company", "community", "group", "team", "sa", "ag",
              "pvt", "oss"}
# Words of a product name that any package could carry, for the test of a link learned from one CVE.
GENERIC_WORDS = {"java", "for", "of", "the", "and", "build", "server", "client", "library", "libraries", "lib",
                 "api", "sdk", "plugin", "red", "hat", "edition", "enterprise", "legacy", "apache", "eclipse",
                 "project", "framework", "platform", "service", "services", "web", "application", "app", "core",
                 "module", "component", "suite", "tool", "tools"}
OTHER_REGISTRY = re.compile(r"npmjs|pypi|rubygems|nuget|crates\.io|packagist|pkg\.go\.dev|proxy\.golang|hex\.pm|"
                            r"pub\.dev|cocoapods", re.I)
MAVEN_REPOSITORY = re.compile(r"maven|repo1\.|central\.sonatype", re.I)
LINE_IN_TEXT = re.compile(r"(?<![\w.])\d+(?:\.\d+)*(?=\.[xX*]\b|\b)")
COORDINATE = re.compile(r"^[a-z][\w-]*(\.[\w-]+)+:[A-Za-z][\w.-]*$")
REPOSITORY_PATH = re.compile(r"/maven2/(.+?)/([^/]+)/?$")
FILES_KEPT = 20


def raw_url(ident: str) -> str:
    """Where the repository keeps a record: cves/2026/101xxx/CVE-2026-101296.json."""
    _, year, number = ident.split("-")
    return f"{RAW}/{year}/{int(number) // 1000}xxx/{ident}.json"


# ---- records ---------------------------------------------------------------------------------------------

def _english(entries) -> str:
    return next((e.get("value", "") for e in entries or [] if (e.get("lang") or "").lower().startswith("en")), "")


def _score(containers: list[dict]) -> dict | None:
    """The CNA's CVSS rating, newest version first; an ADP's (CISA's) when the CNA gave none."""
    for container in containers:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            for metric in container.get("metrics") or []:
                data = metric.get(key)
                if data:
                    return {"version": data.get("version"), "vector": data.get("vectorString"),
                            "score": data.get("baseScore"), "severity": (data.get("baseSeverity") or "").upper() or None,
                            "source": container.get("providerMetadata", {}).get("shortName"), "type": "CNA"
                            if container is containers[0] else "ADP"}
    return None


def _entry(affected: dict, source: str) -> dict | None:
    versions = [{k: v[k] for k in ("status", "version", "lessThan", "lessThanOrEqual", "versionType") if v.get(k)}
                for v in affected.get("versions") or [] if isinstance(v, dict)]
    entry = {"vendor": affected.get("vendor") or "", "product": affected.get("product") or "",
             "package": (affected.get("packageName") or "").strip(), "repository": affected.get("collectionURL") or "",
             "cpes": [c for c in affected.get("cpes") or [] if isinstance(c, str)], "versions": versions,
             "default": affected.get("defaultStatus") or "", "files": (affected.get("programFiles") or [])[:FILES_KEPT],
             "source": source}
    return entry if entry["product"] or entry["package"] or entry["cpes"] else None


def trim(record: dict) -> dict | None:
    """What a candidate needs of a CVE JSON 5 record; the id and state alone for one not published."""
    meta = record.get("cveMetadata") or {}
    ident = meta.get("cveId")
    if not ident:
        return None
    if meta.get("state") != "PUBLISHED":
        return {"id": ident, "state": meta.get("state") or ""}
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = [a for a in containers.get("adp") or [] if isinstance(a, dict)]
    entries = [e for e in (_entry(a, "cna") for a in cna.get("affected") or [] if isinstance(a, dict)) if e]
    # An ADP (CISA's Vulnrichment) adds CPEs to records whose CNA gave none: only those are kept of it.
    entries += [e for e in (_entry(a, "adp") for adp in adps for a in adp.get("affected") or []
                            if isinstance(a, dict) and a.get("cpes")) if e]
    references = list(dict.fromkeys(r["url"] for r in cna.get("references") or [] if isinstance(r, dict)
                                    and r.get("url")))
    tags = {t for t in cna.get("tags") or [] if isinstance(t, str)}
    cwes = sorted({d.get("cweId") for p in cna.get("problemTypes") or [] for d in p.get("descriptions") or []
                   if (d.get("cweId") or "").startswith("CWE-")})
    return {"id": ident, "state": "PUBLISHED", "cna": meta.get("assignerShortName") or "",
            "published": meta.get("datePublished") or "", "updated": meta.get("dateUpdated") or "",
            "title": cna.get("title") or "", "description": _english(cna.get("descriptions")),
            "cvss": _score([cna, *adps]), "cwe": cwes, "disputed": "disputed" in tags,
            "references": references[:nvd.REFERENCES_KEPT],
            "commits": [u for u in references if fixes.COMMIT.match(u)], "affected": entries}


# ---- what an entry names ---------------------------------------------------------------------------------

def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", (text or "").lower())


def key_of(vendor: str, product: str) -> str | None:
    """A product as ``vendor|product``, in words: "The Eclipse Foundation / Eclipse Jetty" and
    "eclipse / jetty.project" are both eclipse|jetty. None for a placeholder product."""
    if (product or "").strip().lower() in PLACEHOLDERS:
        return None
    vendor_words = [] if (vendor or "").strip().lower() in PLACEHOLDERS else _words(vendor)
    vendor_words = [w for w in vendor_words if w not in STOP_WORDS] or vendor_words
    product_words = _words(product)
    while len(product_words) > 1 and product_words[0] in vendor_words:
        product_words = product_words[1:]
    if len(product_words) > 1 and product_words[-1] == "project":
        product_words = product_words[:-1]
    return f"{' '.join(vendor_words)}|{' '.join(product_words)}" if product_words else None


def claims(entry: dict) -> bool:
    """Whether an entry says any version is affected."""
    return entry["default"] == "affected" or any(v.get("status") == "affected" for v in entry["versions"])


def usable(entry: dict) -> bool:
    """A CNA entry that claims affected versions of something that may be a Maven package: not one whose
    collection is another registry (npm, PyPI)."""
    return entry["source"] == "cna" and claims(entry) and not OTHER_REGISTRY.search(entry["repository"])


def package_of(entry: dict) -> tuple[str, str] | None:
    """(``groupId:artifactId``, how) an entry names: "package" when by its package name, "repository" when read
    from its repository URL. CNAs miswrite those paths (org/xerial/snappy-java for org.xerial.snappy), so a
    coordinate read from one counts only for a package known to exist."""
    package, url = entry["package"], entry["repository"]
    if COORDINATE.match(package) and (not url or MAVEN_REPOSITORY.search(url)):
        return package, "package"
    found = REPOSITORY_PATH.search(url) if not package else None
    if found:
        name = f"{found.group(1).replace('/', '.')}:{found.group(2)}"
        if COORDINATE.match(name):
            return name, "repository"
    return None


def module_key(name: str) -> str:
    """A Maven package as its family and module, the same for every build of it: org.bouncycastle:bcprov."""
    return nvd.family("maven", name) + nvd.module_of(name.split(":", 1)[-1])


def cpe_product(cpe: str) -> str | None:
    """``vendor:product`` of an application CPE, in the 2.3 or the 2.2 form."""
    if cpe.startswith("cpe:2.3:"):
        fields = nvd.split_cpe(cpe)
        return f"{fields[3].lower()}:{fields[4].lower()}" if len(fields) > 4 and fields[2] == "a" and fields[4] \
            else None
    fields = cpe[len("cpe:/a:"):].split(":") if cpe.startswith("cpe:/a:") else []
    return f"{fields[0].lower()}:{fields[1].lower()}" if len(fields) > 1 and fields[1] else None


def facets(record: dict) -> tuple[set[str], set[tuple[str, str]], set[str]]:
    """(product keys, packages as (name, how), CPEs) of a record's entries that claim affected versions. Keys and
    packages come from the CNA's own entries outside other registries only; CPEs from an ADP's too."""
    keys, packages, cpes = set(), set(), set()
    for entry in record.get("affected") or []:
        if not claims(entry):
            continue
        cpes |= {p for p in map(cpe_product, entry["cpes"]) if p}
        if not usable(entry):
            continue
        key = key_of(entry["vendor"], entry["product"])
        if key:
            keys.add(key)
        named = package_of(entry)
        if named:
            packages.add(named)
    return keys, packages, cpes


def entries_for(record: dict, basis: str, via: str, name: str, known: Callable[[str], bool]) -> list[dict]:
    """The entries of a record by which it reached a package: those naming a build of its module (cna_package),
    carrying the CPE (cna_cpe) or the product name (cna_learned). ``known``: whether a package exists, for
    coordinates read from a repository URL."""
    out = []
    for entry in record.get("affected") or []:
        if basis == "cna_cpe":
            if claims(entry) and via in {cpe_product(c) for c in entry["cpes"]}:
                out.append(entry)
        elif usable(entry):
            if basis == "cna_learned" and key_of(entry["vendor"], entry["product"]) == via:
                out.append(entry)
            elif basis == "cna_package":
                named = package_of(entry)
                if named and module_key(named[0]) == module_key(name) and (named[1] == "package" or known(named[0])):
                    out.append(entry)
    return out


def product_text(entries: list[dict]) -> str:
    """How the first entry names its product: "Apache Software Foundation / Apache Tomcat"."""
    entry = entries[0] if entries else {}
    return " / ".join(t for t in (entry.get("vendor"), entry.get("product") or entry.get("package")) if t)


def program_classes(entries: list[dict]) -> list[str]:
    """The classes an entry's program files name, where they are paths of main code (src/main/java/...)."""
    return sorted({found[1] for e in entries for path in e["files"] if isinstance(path, str)
                   for found in [fixes.main_source(path)] if found})


def narrows(entry: dict, name: str) -> bool:
    """Whether an entry's package name, an artifactId stem without a groupId (Bouncy Castle writes bcprov,
    bcpg), leaves a package out."""
    package = entry["package"]
    if not package or ":" in package or "/" in package or " " in package:
        return False
    artifact = name.split(":", 1)[-1]
    return not (artifact == package or artifact.startswith(package + "-") or nvd.module_of(artifact) == package)


def _near(a: str, b: str) -> bool:
    return a == b or min(len(a), len(b)) >= 4 and (a.startswith(b) or b.startswith(a))


def stem_match(key: str, name: str) -> bool:
    """Whether a product name reads as a package: a word of it (other than java, server and the like) is a word
    of the artifactId, or its words run together are a part of the groupId (Bouncy Castle, org.bouncycastle) or the
    artifactId. A product named after a distribution (JBoss EAP) does not read as one of its modules."""
    vendor, _, product = key.partition("|")
    group, _, artifact = name.partition(":")
    artifact_words = _words(artifact)
    words = [w for w in _words(f"{vendor} {product}") if w not in GENERIC_WORDS and not w.isdigit()]
    if any(_near(w, a) for w in words for a in artifact_words if not a.isdigit()):
        return True
    joined = "".join(_words(product))
    return bool(joined) and (joined in group.lower().split(".") or joined == "".join(artifact_words))


# ---- versions --------------------------------------------------------------------------------------------

def _plain(text: str | None) -> str:
    text = (text or "").strip()
    return text[1:] if text[:1] in "vV" and text[1:2].isdigit() else text


@dataclass(frozen=True)
class Range:
    start: str  # "" from the first version
    end: str | None  # None: no upper bound; "*" in the record is None too
    inclusive: bool


def _ranges(entry: dict) -> list[tuple[str, Range | str]]:
    """(status, a Range or an exact version) of the entry's readable versions; git commit ranges are not."""
    out = []
    for v in entry["versions"]:
        status = v.get("status")
        if status not in ("affected", "unaffected", "unknown") or (v.get("versionType") or "").lower() == "git":
            continue
        start, below, upto = _plain(v.get("version")), v.get("lessThan"), v.get("lessThanOrEqual")
        if below or upto:
            end = _plain(below or upto)
            if not (end == "*" or VERSIONISH.match(end)):
                continue
            if start.lower() in PLACEHOLDERS or start == "0":
                start = ""
            elif not VERSIONISH.match(start):
                # "Apache Ant 1.9.x" up to 1.9.15 is the 1.9 line; "Apache Ant" below 1.9.0 is from the first.
                line = LINE_IN_TEXT.search(start)
                start = line.group(0) if line and (end == "*" or compare("maven", line.group(0), end) <= 0) else ""
            out.append((status, Range(start, None if end == "*" else end, bool(upto and not below))))
        elif VERSIONISH.match(start) or OPERATOR.match(start):
            out.append((status, start))
    return out


def _covers(item: Range | str, ecosystem: str, version: str) -> bool | None:
    if isinstance(item, str):
        return compare(ecosystem, version, item) == 0 if VERSIONISH.match(item) else \
            in_range(ecosystem, version, item)
    if item.start and compare(ecosystem, version, item.start) < 0:
        return False
    if item.end is None:
        return True
    order = compare(ecosystem, version, item.end)
    return order < 0 or order == 0 and item.inclusive


def status_of(entry: dict, version: str, ecosystem: str = "maven") -> str | None:
    """"affected", "unaffected", or None when the entry does not tell, in the terms of CVE JSON 5: a range that
    covers the version gives its status (an unaffected one first); otherwise the default status. A default of
    affected beside ranges with an upper bound does not tell: versions past those are ones the vendor did not
    look at as often as ones it found unaffected."""
    found = None
    readable = _ranges(entry)
    for status, item in readable:
        if _covers(item, ecosystem, version):
            if status == "unaffected":
                return "unaffected"
            found = found or status
    if found:
        return "affected" if found == "affected" else None
    if entry["default"] == "affected":
        bounded = any(status == "affected" and isinstance(item, Range) and item.end for status, item in readable)
        return None if bounded else "affected"
    if entry["default"] == "unaffected" and (readable or not entry["versions"]):
        return "unaffected"
    return None


def told(statuses) -> str | None:
    """What several entries for the same package say together: affected when any says so, unaffected when all
    do; otherwise they do not tell."""
    statuses = list(statuses)
    if "affected" in statuses:
        return "affected"
    return "unaffected" if statuses and all(s == "unaffected" for s in statuses) else None


def affected_ranges(entries: list[dict]) -> list[Range | str]:
    return [item for e in entries for status, item in _ranges(e) if status == "affected"]


def advisory_ranges(advisory: dict | None) -> list[Range]:
    """The affected lines of a vendor's advisory (see localdb.spring_advisories), each up to its last affected
    version."""
    return [Range(_plain(v["introduced"]), _plain(v["last_affected"]), True)
            for v in (advisory or {}).get("versions") or []]


def advisory_status(advisory: dict | None, version: str, ecosystem: str = "maven") -> str | None:
    """An advisory lists every line it found affected, unsupported ones included ("introduced" left out):
    a version outside them is a fixed one. None when the advisory gives no versions."""
    ranges = advisory_ranges(advisory)
    if not ranges:
        return None
    return "affected" if any(_covers(r, ecosystem, version) for r in ranges) else "unaffected"


def describe(entries: list[dict]) -> str:
    """The affected versions, as nvd.Match.describe words them."""
    return describe_ranges(affected_ranges(entries), any(e["default"] == "affected" for e in entries))


def describe_ranges(ranges: list[Range | str], by_default: bool = False) -> str:
    parts = []
    for item in ranges:
        if isinstance(item, str):
            parts.append(item)
            continue
        bounds = [f">= {item.start}" if item.start else "",
                  (f"<= {item.end}" if item.inclusive else f"< {item.end}") if item.end else ""]
        parts.append(", ".join(b for b in bounds if b) or "all versions")
    if not parts and by_default:
        parts.append("all versions")
    return "; ".join(dict.fromkeys(parts))


def _line(version: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", version)[:2])


def below_listed_lines(ranges: list[Range | str], version: str, ecosystem: str = "maven") -> bool:
    """Whether a version is affected only by a range from the first version up, on a release line older than
    that range's end, where the vendor lists ranges of two or more lines: one it no longer supports and did not
    look at. A single range from the first version up is the vendor saying all earlier versions are affected."""
    ends = [r.end for r in ranges if isinstance(r, Range) and r.end and VERSIONISH.match(r.end)]
    if len({_line(e) for e in ends}) < 2:
        return False
    return any(isinstance(r, Range) and not r.start and r.end and VERSIONISH.match(r.end)
               and _covers(r, ecosystem, version) and _line(version) < _line(r.end) for r in ranges)


# ---- learning which product names a package --------------------------------------------------------------

def learn(attributed: dict[str, set[str]], keys: dict[str, list[tuple[str, dict]]],
          osv_records: Callable[[str], list[dict]]) -> dict[str, dict[str, int]]:
    """product key -> {package: CVEs learned from}. ``attributed``: CVE id -> the Maven packages OSV attributes
    it to; ``keys``: CVE id -> (key, entry) of its CNA record's usable entries. The four conditions of
    nvd.Linker, with the CNA's product name in place of the CPE, from the CVEs whose record names one product
    only; and a link learned from one CVE only must also read as the package (``stem_match``)."""
    single = {}
    for cve, found in keys.items():
        names = {k for k, _ in found}
        if len(names) == 1:
            single[cve] = names.pop()
    by_package: dict[str, set[str]] = defaultdict(set)
    for cve, names in attributed.items():
        for name in names:
            by_package[name].add(cve)
    key_cves: dict[str, set[str]] = defaultdict(set)
    for cve in attributed:
        if cve in single:
            key_cves[single[cve]].add(cve)
    project_cves: dict[str, set[str]] = defaultdict(set)
    for name, cves in by_package.items():
        project_cves[nvd.project("maven", name)] |= cves
    project_counts: dict[str, Counter] = {}

    def in_project(name: str) -> Counter:
        own = nvd.project("maven", name)
        if own not in project_counts:
            project_counts[own] = Counter(single[c] for c in project_cves[own] if c in single)
        return project_counts[own]
    links: dict[str, dict[str, int]] = defaultdict(dict)
    for name, cves in sorted(by_package.items()):
        named = {c: single[c] for c in cves if c in single}
        if not named:
            continue
        counts = Counter(named.values())
        total, top = len(named), max(counts.values())
        home = nvd.family("maven", name)
        records = None
        for key, shared in sorted(counts.items()):
            if shared < nvd.PACKAGE_SHARE * total or shared < nvd.TOP_SHARE * top:
                continue
            same = sum(1 for c in key_cves[key] if any(nvd.family("maven", n) == home for n in attributed[c]))
            if same < nvd.PRODUCT_SHARE * len(key_cves[key]):
                continue
            project = in_project(name)
            if project[key] < nvd.PROJECT_SHARE * sum(project.values()):
                continue
            if len(key_cves[key]) < 2 and not stem_match(key, name):
                continue
            if records is None:
                records = osv_records(name)
            meet = Counter(_meet(records, name, c, [e for k, e in keys[c] if k == key])
                           for c in cves if named.get(c) == key)
            if meet[False] > meet[True]:
                continue
            links[key][name] = len(key_cves[key])
    return dict(links)


def _meet(records: list[dict], name: str, cve: str, entries: list[dict]) -> bool | None:
    """Whether OSV's versions of a package and the CNA's for one CVE have one in common, by the bounds of
    either; None when either states none."""
    intervals, listed = nvd.osv_affected(records, name, cve)
    ranges = affected_ranges(entries)
    bounds = {b for item in ranges for b in
              ([item.start, item.end] if isinstance(item, Range) else re.findall(r"\d[\w.+-]*", item)) if b}
    if not (intervals or listed) or not bounds:
        return None
    # The same fix on both sides, however each spells it: two ranges from the first version up meet on no bound.
    ends = {nvd._release(end) for _, end, _ in intervals if end} - {()}
    if any(isinstance(item, Range) and item.end and nvd._release(item.end) in ends for item in ranges):
        return True
    points = set(listed) | {v for a, b, _ in intervals for v in (a, b) if v and v != "0"} | bounds
    return any(nvd._osv_covers("maven", intervals, listed, p) and
               any(status_of(e, p) == "affected" for e in entries) for p in points)
