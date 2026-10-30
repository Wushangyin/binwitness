"""NVD candidates: public CVE records that name a component's product, which no OSV advisory attributes to a package.

OSV states the affected package of each advisory precisely, but only for advisories somebody attributed to a
package; an unreviewed GitHub advisory, or a CVE GitHub never took up, reaches no package and so no scan.
NVD describes the same CVEs by product (CPE ``vendor:product`` and a version range), which is coarser: one
CPE stands for every module of a product, and NVD also lists the products that bundle a library.

So a candidate is only a lead for manual review. It is kept apart from the findings, and the link from a
package to a CPE is learned from data rather than guessed from names: when the CVEs OSV attributes to a
package mostly carry the same CPE in NVD, that CPE is the package's product. A component whose package has
no such history gets no candidates, and is counted as such.
"""
from __future__ import annotations

import io
import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, replace

from binwitness import cna, fixes
from binwitness.versions import compare
from binwitness.vulns import SEVERITIES

NVD_FEEDS = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_CVE = "https://nvd.nist.gov/vuln/detail"
CVE_ORG = "https://www.cve.org/CVERecord?id="
NOT_IN_NVD = "Not in NVD"
# The ways a CNA's record or a vendor's advisory reaches a package, in the order they are tried.
CNA_PATHS = ("cna_package", "cna_cpe", "cna_learned", "advisory_direct")
FIRST_YEAR = 2002
# The four conditions for linking a CPE with a package, set on the NVD and OSV data of October 2026 (see
# Linker). Products that bundle a library (an appliance, a suite) are what they keep out.
PACKAGE_SHARE = 0.3
TOP_SHARE = 0.5
PRODUCT_SHARE = 0.5
PROJECT_SHARE = 0.25
# Enough to tell which module or language binding a record is about; Oracle's quarterly records list hundreds.
REFERENCES_KEPT = 20
# What compact() stores: 2 adds the commit references with NVD's tags (0.4.4). A copy stored otherwise is
# downloaded again, since only the records NVD changes since would be stored anew.
LAYOUT = 2
LEARNED_FROM_KEPT = 5
SCHEMA = """
CREATE TABLE records(id TEXT PRIMARY KEY, modified TEXT, status TEXT, body BLOB);
CREATE TABLE cpes(vendor TEXT, product TEXT, id TEXT);
CREATE TABLE unanalyzed(id TEXT PRIMARY KEY, status TEXT);
"""
# CPE target_sw values of other language runtimes: a Java library and a Node.js package can share vendor and
# product, and NVD tells them apart only here.
FOREIGN_TARGETS = {
    "maven": {"node.js", "nodejs", "python", "ruby", "rust", "go", "golang", "php", "perl", ".net", "wordpress",
              "drupal", "joomla!", "rubygems", "pypi"},
    "npm": {"java", "python", "ruby", "rust", "go", "golang", "php", "perl", ".net", "wordpress", "drupal",
            "joomla!", "rubygems", "pypi", "maven", "jenkins"},
}
_FEED_ARRAY = re.compile(r'"vulnerabilities"\s*:\s*\[')


def feed_items(stream, chunk: int = 1 << 20) -> Iterator[dict]:
    """The ``cve`` objects of an NVD JSON 2.0 feed, one at a time. A yearly feed is some 300 MB of JSON; read
    whole it would take several GB of memory, so the array is decoded entry by entry as the text arrives."""
    reader = io.TextIOWrapper(stream, encoding="utf-8")
    try:
        yield from _decode(reader, chunk)
        # Read to the end, so that a digest taken over the stream covers all of it.
        while reader.read(chunk):
            pass
    finally:
        reader.detach()


def _decode(reader, chunk: int) -> Iterator[dict]:
    decoder = json.JSONDecoder()
    buffer, ended = "", False
    while True:
        more = reader.read(chunk)
        buffer += more
        found = _FEED_ARRAY.search(buffer)
        if found:
            position = found.end()
            break
        if not more:
            raise ValueError("not an NVD JSON 2.0 feed: no vulnerabilities array")
        buffer = buffer[-64:]
    while True:
        while position < len(buffer) and buffer[position] in " \t\r\n,":
            position += 1
        if position >= len(buffer) or buffer[position] != "]":
            try:
                if position >= len(buffer):
                    raise json.JSONDecodeError("need more", buffer, position)
                item, end = decoder.raw_decode(buffer, position)
            except json.JSONDecodeError:
                if ended:
                    raise ValueError("the feed ends inside an entry") from None
                more = reader.read(chunk)
                ended = not more
                buffer, position = buffer[position:] + more, 0
                continue
            yield item.get("cve") or {}
            position = end
            if position > chunk:
                buffer, position = buffer[position:], 0
            continue
        return


# ---- CPE ------------------------------------------------------------------------------------------------

def split_cpe(name: str) -> list[str]:
    """The fields of a CPE 2.3 formatted string, unescaped (``mysql_connector\\/j`` is ``mysql_connector/j``)."""
    fields, current, escaped = [], [], False
    for character in name:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    fields.append("".join(current))
    return fields


@dataclass(frozen=True)
class Match:
    """One vulnerable CPE match of a CVE record: a product and the versions of it that are affected."""
    vendor: str
    product: str
    version: str
    update: str
    target: str
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None
    # Vulnerable only together with another product (a configuration joined by AND: "running on").
    conditional: bool = False

    @property
    def cpe(self) -> str:
        return f"{self.vendor}:{self.product}"

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, False)}

    def covers(self, ecosystem: str, version: str) -> bool:
        if self.target.lower() in FOREIGN_TARGETS.get(ecosystem, ()):
            return False
        if self.version not in ("*", ""):
            if self.version == "-":
                return False
            stated = self.version if self.update in ("*", "-", "") else f"{self.version}-{self.update}"
            return compare(ecosystem, version, stated) == 0
        if self.start_including and compare(ecosystem, version, self.start_including) < 0:
            return False
        if self.start_excluding and compare(ecosystem, version, self.start_excluding) <= 0:
            return False
        if self.end_including and compare(ecosystem, version, self.end_including) > 0:
            return False
        if self.end_excluding and compare(ecosystem, version, self.end_excluding) >= 0:
            return False
        return True

    def describe(self) -> str:
        if self.version not in ("*", ""):
            return f"{self.version}" + ("" if self.update in ("*", "-", "") else f" {self.update}")
        bounds = [f">= {self.start_including}" if self.start_including else "",
                  f"> {self.start_excluding}" if self.start_excluding else "",
                  f"<= {self.end_including}" if self.end_including else "",
                  f"< {self.end_excluding}" if self.end_excluding else ""]
        text = ", ".join(b for b in bounds if b) or "all versions"
        return text + (f" ({self.target})" if self.target not in ("*", "-", "") else "")


def matches(cve: dict) -> list[Match]:
    """The vulnerable application CPEs of a record. Platforms in an AND configuration (an operating system the
    application runs on) are not vulnerable themselves and are left out; the application is marked as
    conditional."""
    out = []
    for configuration in cve.get("configurations") or []:
        joined = (configuration.get("operator") or "OR").upper() == "AND"
        for node in configuration.get("nodes") or []:
            if node.get("negate"):
                continue
            for entry in node.get("cpeMatch") or []:
                if not entry.get("vulnerable"):
                    continue
                fields = split_cpe(entry.get("criteria", ""))
                if len(fields) < 13 or fields[2] != "a":
                    continue
                match = Match(fields[3].lower(), fields[4].lower(), fields[5], fields[6], fields[10],
                              entry.get("versionStartIncluding"), entry.get("versionStartExcluding"),
                              entry.get("versionEndIncluding"), entry.get("versionEndExcluding"), joined)
                if match not in out:
                    out.append(match)
    return out


# ---- records --------------------------------------------------------------------------------------------

def _english(entries: list[dict]) -> str:
    return next((e.get("value", "") for e in entries or [] if e.get("lang") == "en"), "")


def score(cve: dict) -> dict | None:
    """The CVSS rating NVD itself assigned where there is one (type Primary), else the CNA's; newest version
    first."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rated = sorted(metrics.get(key) or [], key=lambda m: m.get("type") != "Primary")
        if rated:
            data = rated[0].get("cvssData") or {}
            severity = (data.get("baseSeverity") or rated[0].get("baseSeverity") or "").upper()
            return {"version": data.get("version"), "vector": data.get("vectorString"),
                    "score": data.get("baseScore"), "severity": severity or None,
                    "source": rated[0].get("source"), "type": rated[0].get("type")}
    return None


def _fix_refs(cve: dict) -> list[list]:
    """The commit references, beyond the references kept, each with whether NVD tagged it as the patch."""
    tagged: dict[str, bool] = {}
    for reference in cve.get("references") or []:
        url = reference.get("url") or ""
        if fixes.COMMIT.match(url):
            tagged[url] = tagged.get(url, False) or "Patch" in (reference.get("tags") or [])
    return [[url, patch] for url, patch in tagged.items()]


def compact(cve: dict) -> dict:
    """What a candidate needs of a record, a tenth of its size."""
    tags = {t for entry in cve.get("cveTags") or [] for t in entry.get("tags") or []}
    cwes = sorted({d.get("value") for w in cve.get("weaknesses") or [] for d in w.get("description") or []
                   if (d.get("value") or "").startswith("CWE-")})
    return {
        "id": cve.get("id"), "status": cve.get("vulnStatus"), "published": cve.get("published"),
        "modified": cve.get("lastModified"), "disputed": "disputed" in tags,
        "description": _english(cve.get("descriptions")), "cvss": score(cve), "cwe": cwes,
        "kev_date_added": cve.get("cisaExploitAdd"),
        "references": list(dict.fromkeys(r["url"] for r in cve.get("references") or [] if r.get("url")))[
            :REFERENCES_KEPT],
        "fix_refs": _fix_refs(cve),
        "matches": [m.as_dict() for m in matches(cve)],
    }


def match_of(stored: dict) -> Match:
    return Match(**stored)


def cve_ids(record: dict) -> set[str]:
    """CVE ids an OSV record stands for: its own id or its aliases."""
    return {i for i in [record.get("id", ""), *record.get("aliases", [])] if i.startswith("CVE-")}


# ---- learning which CPE names a package ---------------------------------------------------------------

def project(ecosystem: str, name: str) -> str:
    """The publisher a package belongs to: a Maven groupId, an npm scope, or an unscoped npm package itself.
    Ends in the separator when it stands for several packages."""
    if ecosystem == "maven":
        return name.split(":", 1)[0] + ":"
    return name.split("/", 1)[0] + "/" if name.startswith("@") else name


def family(ecosystem: str, name: str) -> str:
    """A project together with its subprojects: a Maven groupId cut to its first three parts, so that
    Tomcat's embedded jars (org.apache.tomcat.embed) count as Tomcat's."""
    if ecosystem == "maven":
        return ".".join(name.split(":", 1)[0].split(".")[:3]) + ":"
    return project(ecosystem, name)


def osv_affected(records: list[dict], name: str, cve: str) -> tuple[list[tuple[str, str | None, bool]], set[str]]:
    """What the OSV records of one CVE say of one package: version intervals (introduced, end or None, end
    included) and the versions they list."""
    intervals, listed = [], set()
    for record in records:
        if cve not in cve_ids(record):
            continue
        for affected in record.get("affected") or []:
            if (affected.get("package") or {}).get("name") != name:
                continue
            listed |= set(affected.get("versions") or [])
            for found in affected.get("ranges") or []:
                if found.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                start = None
                for event in found.get("events") or []:
                    if "introduced" in event:
                        start = event["introduced"]
                    elif start is not None and ("fixed" in event or "last_affected" in event):
                        intervals.append((start, event.get("fixed") or event["last_affected"], "fixed" not in event))
                        start = None
                if start is not None:
                    intervals.append((start, None, False))
    return intervals, listed


def _osv_covers(ecosystem: str, intervals, listed, version: str) -> bool:
    if version in listed:
        return True
    for start, end, included in intervals:
        if start not in ("0", "") and compare(ecosystem, version, start) < 0:
            continue
        if end is None:
            return True
        order = compare(ecosystem, version, end)
        if order < 0 or (included and order == 0):
            return True
    return False


def _release(version: str | None) -> tuple:
    """The leading numbers of a version, trailing zeros dropped: 9.3.24.v20180605 and 9.3.24 are one release."""
    numbers = []
    for token in re.findall(r"\d+|[A-Za-z]+", version or ""):
        if not token.isdigit():
            break
        numbers.append(int(token))
    while numbers and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers)


def _major(version: str | None) -> int | None:
    found = re.match(r"\D*(\d+)", version or "")
    return int(found.group(1)) if found else None


def ranges_meet(ecosystem: str, intervals, listed, found: list[Match]) -> bool | None:
    """Whether OSV's account of a CVE for a package and NVD's for a CPE affect a version in common; None when
    either gives no versions. They meet on the same fix, however each spells it, or on a version either side
    names (a bound, a listed version) that both cover. Two ranges open at the bottom with different fixes do
    not meet: the early versions they share are what a product numbering its own releases shares as well."""
    found = [m for m in found if m.version != "-"]
    if not found or not (intervals or listed):
        return None
    stated = set(listed) | {v for start, end, _ in intervals for v in (start, end) if v and v != "0"}
    top = max((m for m in map(_major, stated) if m is not None), default=None)
    points, usable = set(stated), []
    for m in found:
        if m.version not in ("*", ""):
            points.add(m.version if m.update in ("*", "-", "") else f"{m.version}-{m.update}")
        points |= {v for v in (m.start_including, m.start_excluding, m.end_including, m.end_excluding) if v}
        # "Before 12.2.0.1.22" covers every early version of any package; it says nothing of a package two
        # major versions short of it (a suite that bundles a 2.x library numbers its own releases).
        end = m.end_excluding or m.end_including
        if m.version in ("*", "") and not (m.start_including or m.start_excluding) and end and top is not None \
                and (_major(end) or 0) > top + 1:
            continue
        usable.append(m)
    if any(m.version in ("*", "") and not any((m.start_including, m.start_excluding, m.end_including,
                                                m.end_excluding)) and m.covers(ecosystem, "0") for m in usable):
        return True  # NVD gives every version
    # The same fix on both sides ("before 4.1.125" and "fixed in 4.1.125.Final"), however each spells it.
    ends = {_release(end) for _, end, _ in intervals if end} - {()}
    if any(_release(m.end_excluding or m.end_including) in ends for m in usable):
        return True
    return any(_osv_covers(ecosystem, intervals, listed, p) and any(m.covers(ecosystem, p) for m in usable)
               for p in points)


@dataclass
class Link:
    """The evidence for a link between a package and a CPE, as counts of CVEs."""
    cpe: str
    shared: int  # the package's CVEs that carry the CPE
    package_cves: int  # the package's CVEs that NVD gives any CPE
    product_same_project: int  # the CPE's CVEs that OSV attributes to a package of the same project
    product_attributed: int  # the CPE's CVEs that OSV attributes to any package
    project_shared: int  # the project's CVEs that carry the CPE
    project_cves: int  # the project's CVEs that NVD gives any CPE
    learned_from: list[str]  # the newest of the package's CVEs that carry the CPE, OSV-attributed to it
    ranges_meet: int = 0  # of the package's CVEs that carry the CPE: where NVD's and OSV's versions overlap
    ranges_apart: int = 0  # ... and where they have no version in common
    packages: int = 0  # packages linked with the same CPE

    @property
    def single(self) -> bool:
        """Learned from one CVE of the package only: the weakest link there is."""
        return self.shared == 1

    def as_dict(self) -> dict:
        return {**asdict(self), "single_cve": self.single}


def _cve_order(ident: str) -> tuple:
    parts = ident.split("-")
    return (int(parts[1]), int(parts[2])) if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit() \
        else (0, 0)


class Linker:
    """Learns which CPE stands for a package, from the CVEs that OSV attributes to it and NVD gives a CPE.

    A CPE is linked with a package when

    1. it is on at least 30% of the package's CVEs, and on at least half as many as the package's most
       frequent CPE (one product can go by several names: Oracle has listed Connector/J under three);
    2. at least half of its CVEs that OSV attributes to any package belong to the package's project or a
       subproject of it: a product that bundles libraries collects the CVEs of many projects;
    3. it is on at least a quarter of the project's CVEs: a bundling product that shipped one module of a large
       project can carry most of that module's few CVEs, never most of the project's;
    4. on no fewer of those CVEs than not, NVD's versions for the CPE overlap OSV's for the package: a product
       that bundles the package numbers its own releases, which no version of the package falls in.
    """

    def __init__(self, db):
        self.db = db
        self._links: dict[tuple[str, str], dict[str, Link]] = {}
        self._apart: dict[tuple[str, str], list[str]] = {}
        self._products: dict[str, tuple[list[str], dict[str, set]]] = {}
        self._projects: dict[tuple[str, str], tuple[Counter, int]] = {}
        self._records: dict[str, dict | None] = {}
        self._modules: dict[str, dict[str, str]] = {}

    def record(self, ident: str) -> dict | None:
        if ident not in self._records:
            self._records[ident] = self.db.nvd_record(ident)
        return self._records[ident]

    def product(self, cpe: str) -> tuple[list[str], dict[str, set]]:
        """The CPE's CVE ids, and the packages (ecosystem, name) OSV attributes each of them to."""
        if cpe not in self._products:
            ids = self.db.nvd_ids(cpe)
            self._products[cpe] = (ids, self.db.osv_attribution(ids))
        return self._products[cpe]

    def _counts(self, cves) -> tuple[Counter, int]:
        cpes = self.db.nvd_cpes(cves)
        return Counter(q for c in cpes for q in cpes[c]), len(cpes)

    def _project(self, ecosystem: str, key: str) -> tuple[Counter, int]:
        if (ecosystem, key) not in self._projects:
            self._projects[(ecosystem, key)] = self._counts(self.db.osv_project_cves(ecosystem, key))
        return self._projects[(ecosystem, key)]

    def links(self, ecosystem: str, name: str) -> dict[str, Link]:
        if (ecosystem, name) in self._links:
            return self._links[(ecosystem, name)]
        cpes = self.db.nvd_cpes(self.db.osv_cves(ecosystem, name))
        counts, total = Counter(q for c in cpes for q in cpes[c]), len(cpes)
        top = max(counts.values(), default=0)
        own, home = project(ecosystem, name), family(ecosystem, name)
        found, apart, records = {}, [], None
        for cpe, shared in sorted(counts.items()):
            if shared < PACKAGE_SHARE * total or shared < TOP_SHARE * top:
                continue
            ids, attributed = self.product(cpe)
            named = [c for c in ids if attributed.get(c)]
            same = sum(1 for c in named if any(e == ecosystem and family(e, n) == home for e, n in attributed[c]))
            if not named or same < PRODUCT_SHARE * len(named):
                continue
            in_project, project_total = self._project(ecosystem, own)
            if in_project[cpe] < PROJECT_SHARE * project_total:
                continue
            carrying = sorted((c for c in cpes if cpe in cpes[c]), key=_cve_order)
            if records is None:
                records = self.db.osv_records(ecosystem, name)
            meet = Counter(ranges_meet(ecosystem, *osv_affected(records, name, c),
                                       [m for m in map(match_of, (self.record(c) or {}).get("matches", []))
                                        if m.cpe == cpe]) for c in carrying)
            if meet[False] > meet[True]:
                apart.append(cpe)
                continue
            found[cpe] = Link(cpe, shared, total, same, len(named), in_project[cpe], project_total,
                              carrying[-LEARNED_FROM_KEPT:][::-1], ranges_meet=meet[True], ranges_apart=meet[False])
        self._links[(ecosystem, name)], self._apart[(ecosystem, name)] = found, apart
        return found

    def apart(self, ecosystem: str, name: str) -> list[str]:
        """CPEs that met the first three conditions for the package but whose versions never meet its own."""
        self.links(ecosystem, name)
        return self._apart[(ecosystem, name)]

    def packages(self, ecosystem: str, cpe: str) -> int:
        """How many packages the CPE is linked with: a product's CPE stands for all of its modules."""
        ids, attributed = self.product(cpe)
        names = sorted({n for c in ids for e, n in attributed.get(c, ()) if e == ecosystem})
        return sum(1 for n in names if cpe in self.links(ecosystem, n))

    def modules(self, home: str) -> dict[str, str]:
        """artifactId -> groupId of the Maven packages of a family (see :func:`family`) that OSV has advisories for."""
        if home not in self._modules:
            base = home[:-1]
            names = self.db.osv_names("maven", base + ":") + self.db.osv_names("maven", base + ".")
            self._modules[home] = {n.split(":", 1)[1]: n.split(":", 1)[0] for n in names
                                   if ":" in n and family("maven", n) == home}
        return self._modules[home]


# ---- what a record's text names -------------------------------------------------------------------------

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
# groupId:artifactId, the way some CNAs name the one module of a project a record is about.
_COORDINATE = re.compile(r"(?<![\w.:/-])([a-z][\w-]*(?:\.[\w-]+)+):([A-Za-z][\w.-]*[A-Za-z0-9])(?![\w:])")
# A module is published in several builds, told apart by a suffix: bcpkix-jdk18on and bcpkix-fips are both bcpkix.
_BUILD = re.compile(r"(?:-(?:fips|jdk\d+(?:on|to\d+)?|lts\d+on|jre\d+))+$")
_ARTIFACT = re.compile(r"(?<![\w./:@-])([a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+)(?![\w-])")
_QUALIFIED_CLASS = re.compile(r"(?<![\w.$/])((?:[a-z_][a-z0-9_]*\.){2,}[A-Z][\w$]*)")
_WORD = re.compile(r"(?<![\w.$])([A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*)(?![\w$])")
# A name followed by one of its members (HTTP2Flusher.terminated, Parser.parse()): a class, however short.
_MEMBER = re.compile(r"(?<![\w.$])([A-Z][A-Za-z0-9]*[a-z][A-Za-z0-9]*)\.([A-Za-z_]\w*)(\()?")
_HUMP = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_LANGUAGES = {
    "Java": r"\bJava\b(?!\s*Script|\s?ME\b)|\bJVM\b|Connector/J\b",
    "Java ME": r"\bJava\s?ME\b",
    "Kotlin": r"\bKotlin\b", "Scala": r"\bScala\b", "Groovy": r"\bGroovy\b",
    "JavaScript": r"\bJavaScript\b|\bTypeScript\b|\bJS\b",
    "Node.js": r"\bNode\.?js\b|Connector/Node\.js",
    "Go": r"\bGo\b|\bgolang\b", "C++": r"C\+\+", "C#": r"C#", ".NET": r"\.NET\b|Connector/NET\b",
    "C": r"\bc_glib\b|\bC/GLib\b|Connector/C\b(?!\+)|Connector/ODBC\b|\bC (?:client|cli|library|bindings?|API)\b",
    "D": r"\bD (?:lang(?:uage)?|bindings?)\b",
    "Python": r"\bPython\b", "Ruby": r"\bRuby\b", "Rust": r"\bRust\b", "PHP": r"\bPHP\b", "Perl": r"\bPerl\b",
    "Haskell": r"\bHaskell\b", "Erlang": r"\bErlang\b", "Lua": r"\bLua\b", "Swift": r"\bSwift\b",
    "Dart": r"\bDart\b", "Delphi": r"\bDelphi\b",
}
_LANGUAGE_PATTERNS = {label: re.compile(pattern) for label, pattern in _LANGUAGES.items()}
# Where bindings are named, a name in lower case is a language all the same (Apache Thrift's "go bindings").
_LANGUAGE_PATTERNS_ANY_CASE = {label: re.compile(pattern, re.I) for label, pattern in _LANGUAGES.items()}
_BINDINGS = re.compile(r"\bbindings\b", re.I)
# What a list of bindings cannot reach back past: a sentence, or the "in" of "vulnerability in Apache Thrift ...".
_CLAUSE = re.compile(r"\.\s|[;:\n]|\b(?:in|of|for|with|from|by)\s", re.I)
BINDINGS_REACH = 120
# A package's own languages, and the ones that say nothing about a binding when named (a cross-site scripting
# record of a Java library speaks of JavaScript): JavaScript named as bindings still does.
OWN_LANGUAGES = {"maven": {"Java", "Kotlin", "Scala", "Groovy"}, "npm": {"JavaScript", "Node.js"}}
NEUTRAL_LANGUAGES = {"maven": {"JavaScript", "Node.js"}, "npm": set()}
CLASS_WORD_HUMPS = 3


def module_of(artifact: str) -> str:
    """An artifactId without the build it names."""
    return _BUILD.sub("", artifact) or artifact


def speaks_for(named: set[str], name: str) -> bool:
    """Whether a record that names these modules (``groupId:artifactId``) speaks for a package: one of them is
    a build of it, or names a module the package's own name begins with (bc-fips, the provider of the FIPS
    edition, for bcprov). A near miss keeps a module rather than leaving it out."""
    own = module_of(name.split(":", 1)[-1])
    return any(own.startswith(module_of(m.split(":", 1)[-1])) for m in named)


def _humps(word: str) -> int:
    """Words a camel-case name is made of: IESEngine has two, UrlFilenameViewController four."""
    return sum(1 for part in _HUMP.findall(word) if not part.isdigit())


def _bound_languages(text: str) -> list[str]:
    """The languages a text names bindings of, in any case: "Thrift nodejs and D lang bindings"."""
    found = []
    for match in _BINDINGS.finditer(text):
        reach = max(0, match.start() - BINDINGS_REACH)
        start = max((c.end() for c in _CLAUSE.finditer(text, reach, match.start())), default=reach)
        phrase = text[start:match.end()]
        found += [label for label, pattern in _LANGUAGE_PATTERNS_ANY_CASE.items() if pattern.search(phrase)]
    return list(dict.fromkeys(found))



@dataclass(frozen=True)
class Naming:
    """What a record's description names: Maven modules, languages, Java classes, other CVEs. ``builds`` are
    artifactIds named with a build (bcpkix-fips) and no groupId: whose they are is up to the family at hand."""
    modules: tuple[str, ...]
    builds: tuple[str, ...]
    languages: tuple[str, ...]
    classes: tuple[str, ...]
    cves: frozenset
    # Two-word names known to be classes, by a member named after them or by a fix that changed a class of
    # that name: missing from a jar, they count.
    confirmed: tuple[str, ...] = ()
    # Languages named as bindings: never neutral (Apache Thrift's "all JS bindings").
    bound: tuple[str, ...] = ()

    @classmethod
    def of(cls, record: dict | None, is_class=None, fixed: Iterable[str] = ()) -> "Naming":
        """``is_class``: whether a word is the simple name of a class in some jar at hand, which makes a
        two-word name (CertificatePinner) count; without it only longer names do. ``fixed``: the classes the
        record's fix changed, which make a two-word name count too (MqttEncoder, when no jar at hand has it)."""
        text = (record or {}).get("description") or ""
        modules = tuple(dict.fromkeys(f"{g}:{a}" for g, a in _COORDINATE.findall(text)))
        builds = tuple(dict.fromkeys(a for a in _ARTIFACT.findall(text) if module_of(a) != a))
        bound = _bound_languages(text)
        languages = tuple(dict.fromkeys(
            [label for label, pattern in _LANGUAGE_PATTERNS.items() if pattern.search(text)] + bound))
        qualified = list(dict.fromkeys(_QUALIFIED_CLASS.findall(text)))
        tails = {q.rsplit(".", 1)[1] for q in qualified}
        # A member of 2-4 letters is more often a domain or a file type (Node.js, Socket.IO) than a field.
        referenced = {w for w, member, call in _MEMBER.findall(text)
                      if call or len(member) >= 5 or any(c.isupper() for c in member)}
        referenced |= {f.rsplit(".", 1)[-1] for f in fixed}
        # A bare word counts when it reads as a class name (UrlFilenameViewController), or when it is one in a
        # jar at hand, or is followed by a member; WebFlux or GitHub could as well be a product or a concept.
        words = [w for w in dict.fromkeys(_WORD.findall(text)) if w not in tails and (
                 _humps(w) >= CLASS_WORD_HUMPS or _humps(w) == 2 and (
                     w in referenced or is_class is not None and is_class(w)))]
        return cls(modules, builds, languages, tuple(qualified + words),
                   frozenset(_CVE.findall(text)) - {(record or {}).get("id")},
                   tuple(w for w in words if w in referenced and _humps(w) < CLASS_WORD_HUMPS), tuple(bound))

    def modules_of(self, ecosystem: str, home: str, group_of=None) -> set[str]:
        """The modules named that belong to a family: the record is about those, not the family's others.
        ``group_of(artifact)``: the groupId of the family's module by that artifactId or another build of it, None
        when the family has no such module; builds are read only with it."""
        if ecosystem != "maven":
            return set()
        named = {m for m in self.modules if family(ecosystem, m) == home}
        if group_of:
            named |= {f"{group}:{a}" for a in self.builds for group in [group_of(a)] if group}
        return named

    def other_language_only(self, ecosystem: str) -> bool:
        named = set(self.languages) - NEUTRAL_LANGUAGES.get(ecosystem, set()) | set(self.bound)
        own = OWN_LANGUAGES.get(ecosystem, set())
        return bool(named) and not named & own

    def placed(self, classes: set[str] | None, unsure: set[str] = frozenset()) -> tuple[list[str] | None,
                                                                                      list[str] | None]:
        """(named classes the jar holds, named classes it does not); None for both when its entries are
        unknown. ``unsure``: entries it may or may not hold (a shaded library's, see scan._Listings). A relocated
        (shaded) copy of a class counts as held, and the case of a name is not trusted. The classes it does not
        hold are none when it holds, or may hold, any of them: a record names the classes a flaw goes through,
        the JDK's (X509TrustManager) among them."""
        if classes is None:
            return None, None
        own, maybe = _class_index(classes), _class_index(unsure)
        held, missing, may_hold = [], [], False
        for name in self.classes:
            # A two-word name missing from the jar says little: BigInteger is the JDK's, not this library's;
            # unless it is known to be a class (``confirmed``).
            if _holds(own, name):
                held.append(name)
            elif _holds(maybe, name):
                may_hold = True
            elif name.startswith("java."):
                continue  # only the JDK may define classes in java.*
            elif "." in name or _humps(name) >= CLASS_WORD_HUMPS or name in self.confirmed:
                missing.append(name)
        return held, [] if held or may_hold else missing


def _class_index(entries: set[str]) -> tuple[set[str], set[str]]:
    # Records misspell the case now and then (UrlFileNameViewController).
    lowered = {e.lower() for e in entries}
    return lowered, {part for entry in lowered for part in entry.rsplit("/", 1)[-1][:-len(".class")].split("$")}


def _holds(index: tuple[set[str], set[str]], name: str) -> bool:
    lowered, simple = index
    if "." in name:
        path = name.replace(".", "/").lower() + ".class"
        return any(e == path or e.endswith("/" + path) for e in lowered)
    return name.lower() in simple


# ---- candidates -----------------------------------------------------------------------------------------

def attach(db, items: list[dict], vulnerabilities: dict, kev_dates: dict, datasets: dict[str, str],
           reason: str | None, listings=None) -> tuple[dict, dict, dict]:
    """(candidates by CVE id, links by purl, summary). ``datasets``: ecosystem -> its OSV dataset name;
    ``reason``: why candidates cannot be looked for at all, if so; ``listings``: the jar entries at hand, with
    ``of(item)`` (the class entries of the jar holding an item, None when unknown), ``has_class(name)`` and,
    optionally, ``unsure(item)`` (entries it may or may not hold)."""
    if reason:
        return {}, {}, {"checked": False, "not_checked": reason}
    linker = Linker(db)
    table, links_of = {}, {}
    linked = without = 0
    not_checked: Counter = Counter()
    left_out: Counter = Counter()
    refused: set = set()
    packages: dict[tuple[str, str], int] = {}
    namings: dict[str, Naming] = {}
    # Every build of a module, by family: a record that names one reaches the others.
    by_module: dict[tuple[str, str], list[dict]] = {}
    at_hand: dict[str, dict[str, str]] = {}
    for item in items:
        if item["ecosystem"] == "maven" and ":" in item["name"]:
            home = family("maven", item["name"])
            group, artifact = item["name"].split(":", 1)
            by_module.setdefault((home, module_of(artifact)), []).append(item)
            at_hand.setdefault(home, {})[artifact] = group
    named_modules: set = set()
    groups: dict[str, Callable[[str], str | None]] = {}
    named_in: dict[tuple[str, str], set[str]] = {}
    advisory_in: dict[tuple[str, str], set[str]] = {}

    held: dict[str, tuple[set | None, set]] = {}
    named_items = {item["purl"]: item for item in items}

    cna_bodies: dict[str, dict | None] = {}

    def cna_record(ident: str) -> dict | None:
        if ident not in cna_bodies:
            cna_bodies[ident] = db.cna_records([ident]).get(ident) if db.has("cvelist") else None
        return cna_bodies[ident]

    def naming(ident: str) -> Naming:
        if ident not in namings:
            is_class = listings.has_class if listings else None
            fixed = (db.fix_of(ident) or {}).get("classes", [])
            record = linker.record(ident)
            if record is not None:
                namings[ident] = Naming.of(record, is_class, fixed)
            else:
                # NVD has no text of it yet: the CNA's, with the classes its program files name.
                own = cna_record(ident) or {}
                facts = Naming.of(own, is_class, fixed)
                files = [c for c in cna.program_classes(own.get("affected") or []) if c not in facts.classes]
                namings[ident] = replace(facts, classes=facts.classes + tuple(files))
        return namings[ident]

    def group_of(home: str):
        """Finds the groupId of a family's module by artifactId, or by another build of it: among the packages OSV
        has advisories for, the jars at hand and, when installed, the hash index of Maven Central."""
        if home not in groups:
            known = {**linker.modules(home), **at_hand.get(home, {})}
            builds = {module_of(a): g for a, g in sorted(known.items())}
            groups[home] = lambda a: known.get(a) or builds.get(module_of(a)) or next(
                (g for g in db.maven_groups(a) if family("maven", f"{g}:{a}") == home), None)
        return groups[home]

    def modules_named(ident: str, ecosystem: str, home: str) -> set[str]:
        if (ident, home) not in named_in:
            named_in[(ident, home)] = naming(ident).modules_of(ecosystem, home, group_of(home))
        return named_in[(ident, home)]

    def advisory_named(ident: str, ecosystem: str, home: str) -> set[str]:
        """The family's modules that the vendor's own advisory names. A vendor may name the module a feature is
        used through rather than the shared one the flaw is in: they reach those modules, and only flag the
        others."""
        if (ident, home) not in advisory_in:
            modules = (db.advisory_modules(ident) or []) if ecosystem == "maven" else []
            advisory_in[(ident, home)] = {m for m in modules if family("maven", m) == home}
        return advisory_in[(ident, home)]

    def entries(item: dict) -> tuple[set | None, set]:
        if item["purl"] not in held:
            unsure = getattr(listings, "unsure", None)
            held[item["purl"]] = (listings.of(item), unsure(item) if unsure else set()) if listings else (None, set())
        return held[item["purl"]]

    def placed(ident: str, item: dict) -> tuple[list | None, list | None]:
        facts = naming(ident)
        return facts.placed(*entries(item)) if facts.classes else ([], [])

    def hit_of(ident: str, cpe: str, ecosystem: str, version: str) -> Match | None:
        return next((m for m in map(match_of, (linker.record(ident) or {}).get("matches", []))
                     if m.cpe == cpe and m.covers(ecosystem, version)), None)

    def add(ident: str, item: dict, cpe: str, hit: Match, basis: str, single: bool):
        entry = table.get(ident) or table.setdefault(ident, _candidate(linker.record(ident), kev_dates))
        entry["affects"].setdefault(item["purl"], {"cpe": cpe, "versions": hit.describe(),
                                                   "conditional": hit.conditional, "basis": basis,
                                                   "single_cve_link": single, "versions_from": "nvd",
                                                   "below_listed_lines": False, "cna_product": ""})

    item_links: dict[str, dict[str, Link]] = {}
    for item in items:
        ecosystem = item["ecosystem"]
        problem = db.cve_index_missing(datasets.get(ecosystem))
        if problem:
            not_checked[problem] += 1
            continue
        links = linker.links(ecosystem, item["name"])
        item_links[item["purl"]] = links
        refused |= {(ecosystem, item["name"], cpe) for cpe in linker.apart(ecosystem, item["name"])}
        if not links or not item["version"]:
            without += 1
            continue
        linked += 1
        for link in links.values():
            if (ecosystem, link.cpe) not in packages:
                packages[(ecosystem, link.cpe)] = linker.packages(ecosystem, link.cpe)
            link.packages = packages[(ecosystem, link.cpe)]
        links_of[item["purl"]] = {cpe: link.as_dict() for cpe, link in links.items()}
        own = _own_ids(item, vulnerabilities)
        home = family(ecosystem, item["name"])
        for cpe, link in links.items():
            ids, attributed = linker.product(cpe)
            for ident in ids:
                if ident in own or attributed.get(ident):
                    continue
                hit = hit_of(ident, cpe, ecosystem, item["version"])
                if hit is None:
                    continue
                modules = modules_named(ident, ecosystem, home)
                if modules or advisory_named(ident, ecosystem, home):
                    named_modules.add((ident, cpe, ecosystem, home))
                if modules:
                    # An all-in-one jar that holds the named module's classes stays.
                    if not speaks_for(modules, item["name"]) and not placed(ident, item)[0]:
                        left_out["names_another_module"] += 1
                        continue
                add(ident, item, cpe, hit, "learned", link.single)
    # A record that names its module reaches that module, in any build, even where no CPE could be learned for
    # it (a module without CVEs of its own, or one inside an all-in-one jar), through the CPE learned for the
    # others; so does the vendor's advisory of it.
    for ident, cpe, ecosystem, home in sorted(named_modules):
        stated = modules_named(ident, ecosystem, home)
        for name in sorted(stated | advisory_named(ident, ecosystem, home)):
            for item in by_module.get((home, module_of(name.split(":", 1)[1])), []):
                if not item["version"] or item["purl"] in table.get(ident, {}).get("affects", {}) \
                        or ident in _own_ids(item, vulnerabilities):
                    continue
                hit = hit_of(ident, cpe, ecosystem, item["version"])
                if hit is not None:
                    add(ident, item, cpe, hit, "named" if name in stated else "advisory", False)

    # The CNAs' own records and the vendors' advisories, for what NVD cannot tell: records it has given no CPE
    # yet, and, where a record or advisory names the package itself, records whose CPEs are not linked with it.
    reaching: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for item in items:
        name = item["name"]
        if item["ecosystem"] != "maven" or ":" not in name or not item["version"] or item["purl"] not in item_links:
            continue
        module, found = cna.module_key(name), {}
        if db.has("cvelist"):
            for package, ident, how in db.cna_packages(module):
                if how == "package" or db.known_package(package):
                    found.setdefault(ident, []).append(("cna_package", package))
            for cpe in sorted(item_links[item["purl"]]):
                for ident in db.cna_cpe_ids(cpe):
                    found.setdefault(ident, []).append(("cna_cpe", cpe))
            for key in db.cna_links(name):
                for ident in db.cna_key_ids(key):
                    found.setdefault(ident, []).append(("cna_learned", key))
        for ident in db.advised(module):
            found.setdefault(ident, []).append(("advisory_direct", ""))
        if found:
            reaching[item["purl"]] = found
    every = sorted({i for found in reaching.values() for i in found})
    attribution, nvd_statuses = db.osv_attribution(every), db.nvd_status(every)
    explicit = {i for i, named_by in (db.cna_named_packages(every) if db.has("cvelist") else {}).items()
                if any(how == "package" or db.known_package(p) for p, how in named_by)}

    def candidate_of(ident: str) -> dict:
        record = linker.record(ident)
        if record is not None:
            return _candidate(record, kev_dates)
        return _cna_candidate(cna_record(ident) or {"id": ident}, nvd_statuses.get(ident), kev_dates)

    for purl, found in sorted(reaching.items()):
        item = named_items[purl]
        name, version, own = item["name"], item["version"], _own_ids(item, vulnerabilities)
        home, linked_here = family("maven", name), item_links[purl]
        for ident, paths in sorted(found.items()):
            if ident in own or attribution.get(ident) or purl in table.get(ident, {}).get("affects", {}):
                continue
            record = linker.record(ident)
            nvd_cpes = {match_of(m).cpe for m in (record or {}).get("matches", [])}
            if nvd_cpes & set(linked_here):
                continue
            left = None
            undecided = False
            for basis, via in sorted(dict.fromkeys(paths), key=lambda p: CNA_PATHS.index(p[0])):
                # A product name or a CPE stands for a package only until NVD has analysed the record, and
                # not for a record that names its packages.
                if basis in ("cna_cpe", "cna_learned") and (record is not None or ident in explicit):
                    continue
                if basis == "advisory_direct":
                    advisory = db.advisory(ident)
                    status, ranges = cna.advisory_status(advisory, version), cna.advisory_ranges(advisory)
                    versions, product, single = cna.describe_ranges(ranges), advisory.get("project") or "", False
                else:
                    own_record = cna_record(ident)
                    chosen = cna.entries_for(own_record, basis, via, name, db.known_package) if own_record else []
                    if not chosen:
                        continue
                    if basis != "cna_package":
                        narrowed = [e for e in chosen if not cna.narrows(e, name)]
                        if not narrowed:
                            left = "package_name_narrows"
                            continue
                        chosen = narrowed
                        modules = modules_named(ident, "maven", home)
                        if modules and not speaks_for(modules, name) and not placed(ident, item)[0]:
                            left = "names_another_module"
                            continue
                    status = cna.told(cna.status_of(e, version) for e in chosen)
                    ranges, versions = cna.affected_ranges(chosen), cna.describe(chosen)
                    product = cna.product_text(chosen)
                    single = linked_here[via].single if basis == "cna_cpe" else \
                        basis == "cna_learned" and db.cna_links(name).get(via) == 1
                if status is None:
                    undecided = True
                    continue
                if status == "affected":
                    entry = table.get(ident) or table.setdefault(ident, candidate_of(ident))
                    entry["affects"][purl] = {
                        "cpe": via if basis == "cna_cpe" else "", "versions": versions, "conditional": False,
                        "basis": basis, "single_cve_link": single,
                        "versions_from": "advisory" if basis == "advisory_direct" else "cna",
                        "below_listed_lines": cna.below_listed_lines(ranges, version), "cna_product": product}
                left = undecided = None
                break
            if left:
                left_out[left] += 1
            elif undecided:
                left_out["versions_not_told"] += 1
    named = {item["purl"]: item for item in items}
    meta = db.cna_meta(table) if db.has("cvelist") else {}
    for ident, entry in table.items():
        facts = naming(ident)
        entry["record_from"] = "nvd" if linker.record(ident) is not None else "cna"
        entry["cna"], entry["cna_published"], entry["cna_updated"] = meta.get(ident) or (None, None, None)
        modules = sorted({m for (i, _), found in named_in.items() if i == ident for m in found} - set(facts.modules))
        entry["modules_named"], entry["languages_named"] = [*facts.modules, *modules], list(facts.languages)
        entry["classes_named"] = list(facts.classes)
        entry["advisory_modules"] = db.advisory_modules(ident) or []
        fix = db.fix_of(ident) or {}
        entry["fix_commits"], entry["fix_commits_elsewhere"] = fix.get("commits", []), fix.get("elsewhere", [])
        entry["fixed_classes"], entry["classes_added_by_fix"] = fix.get("classes", []), fix.get("classes_added", [])
        entry["fix_source_directories"], entry["fixed_classes_from"] = fix.get("source_directories", []), \
            fix.get("classes_from")
        for ref, affected in entry["affects"].items():
            item = named[ref]
            advised = {module_of(m.split(":", 1)[1])
                       for m in advisory_named(ident, item["ecosystem"], family(item["ecosystem"], item["name"]))}
            affected["advisory_names_another_module"] = bool(advised) and \
                module_of(item["name"].split(":", 1)[-1]) not in advised
            affected["related_findings"] = _related(item, ident, facts, vulnerabilities, linker)
            affected["other_language_only"] = facts.other_language_only(item["ecosystem"])
            affected["classes_in_jar"], affected["classes_not_in_jar"] = placed(ident, item)
            # A jar of the affected versions holds what the fix changed, unless the flaw is in another module.
            own, unsure = entries(item)
            fixed = fixes.held(entry["fixed_classes"], own) if entry["fixed_classes"] else []
            affected["fixed_classes_in_jar"] = fixed
            affected["fixed_classes_not_in_jar"] = fixed == [] and bool(entry["fixed_classes"]) \
                and not fixes.held(entry["fixed_classes"], unsure)
    table = dict(sorted(table.items()))
    pairs = [a for c in table.values() for a in c["affects"].values()]
    summary = {
        "checked": linked + without > 0, "not_checked": None if linked + without else
        "; ".join(not_checked) or "no components",
        "total": len(table),
        "pairs": len(pairs),
        "by_severity": {s: sum(1 for c in table.values() if c["severity"] == s) for s in SEVERITIES},
        "disputed": sum(1 for c in table.values() if c["disputed"]),
        "known_exploited": sum(1 for c in table.values() if c["kev_date_added"]),
        "only_from_single_cve_links": sum(1 for c in table.values()
                                          if all(a["single_cve_link"] for a in c["affects"].values())),
        # Flags on component pairs, for whoever reviews them: none takes a pair out.
        "pairs_flagged": {
            "same_flaw_as_a_finding": sum(1 for a in pairs if a["related_findings"]),
            "other_language_only": sum(1 for a in pairs if a["other_language_only"]),
            "named_classes_not_in_jar": sum(1 for a in pairs if a["classes_not_in_jar"] and not a["classes_in_jar"]),
            "advisory_names_another_module": sum(1 for a in pairs if a["advisory_names_another_module"]),
            "fixed_classes_not_in_jar": sum(1 for a in pairs if a["fixed_classes_not_in_jar"]),
            "below_listed_lines": sum(1 for a in pairs if a["below_listed_lines"]),
        },
        "fix_commits": _fix_counts(table) if db.has("fixes") else None,
        "pairs_reached_by_name": sum(1 for a in pairs if a["basis"] == "named"),
        "pairs_reached_by_advisory": sum(1 for a in pairs if a["basis"] == "advisory"),
        "pairs_by_basis": dict(sorted(Counter(a["basis"] for a in pairs).items())),
        "pairs_versions_from": dict(sorted(Counter(a["versions_from"] for a in pairs).items())),
        "records_from_cna": sum(1 for c in table.values() if c["record_from"] == "cna"),
        "pairs_left_out": dict(left_out),
        "links_refused": {"version_ranges_apart": len(refused)},
        "components": {"with_link": linked, "without_link": without, "not_checked": sum(not_checked.values())},
        "components_not_checked_because": dict(not_checked),
        "nvd_records_without_cpe": db.nvd_without_cpe(),
        # An online scan's findings are as of the scan; its candidates are as of these copies.
        "data_as_of": {n: db.data_as_of(n) for n in ["nvd", *sorted(set(datasets.values())), "cvelist", "spring",
                                                     "fixes"] if db.has(n)},
    }
    return table, links_of, summary


def _fix_counts(table: dict) -> dict:
    """How far the fixes the candidates cite were read: commits by what reading them gave, and candidates by the
    commits their fixed classes come from."""
    commits = {c["url"]: c["read"] for entry in table.values() for c in entry["fix_commits"]}
    flagged = Counter(entry["fixed_classes_from"] for entry in table.values()
                      for a in entry["affects"].values() if a["fixed_classes_not_in_jar"])
    return {"candidates_citing_a_commit": sum(1 for e in table.values() if e["fix_commits"] or e["fix_commits_elsewhere"]),
            "candidates_with_fixed_classes": sum(1 for e in table.values() if e["fixed_classes"]),
            "commits": dict(sorted(Counter(commits.values()).items())),
            "commits_elsewhere": len({u for e in table.values() for u in e["fix_commits_elsewhere"]}),
            "candidates_by_classes_from": dict(sorted(Counter(e["fixed_classes_from"] for e in table.values()
                                                              if e["fixed_classes_from"]).items())),
            "pairs_flagged_by_classes_from": dict(sorted(flagged.items()))}


def _own_ids(item: dict, vulnerabilities: dict) -> set[str]:
    return {a for k in item.get("vulnerabilities") or [] for a in [k, *vulnerabilities[k]["aliases"]]}


def _related(item: dict, ident: str, facts: Naming, vulnerabilities: dict, linker: Linker) -> list[str]:
    """The component's findings that are the same flaw as a candidate, as far as either record says so (a
    copy of a flaw elsewhere gets its own CVE, which refers to the original)."""
    out = []
    for key in item.get("vulnerabilities") or []:
        ids = {a for a in [key, *vulnerabilities[key]["aliases"]] if a.startswith("CVE-")}
        if ids & facts.cves or any(ident in Naming.of(linker.record(i)).cves for i in sorted(ids)):
            out.append(key)
    return out


def _cna_candidate(record: dict, nvd_status: str | None, kev_dates: dict) -> dict:
    """A candidate from a CNA's record, for a CVE NVD has not given a CPE (``nvd_status``: NVD's status of it,
    None when NVD does not have it yet). A record not kept with its text has the id only."""
    cvss = record.get("cvss") or {}
    severity = cvss.get("severity") if cvss.get("severity") in SEVERITIES else "UNKNOWN"
    ident = record["id"]
    return {"id": ident, "status": nvd_status or NOT_IN_NVD, "disputed": bool(record.get("disputed")),
            "severity": severity, "cvss_score": cvss.get("score"), "cvss_vector": cvss.get("vector"),
            "cvss_source": cvss.get("source"), "kev_date_added": kev_dates.get(ident),
            "published": record.get("published") or None, "modified": record.get("updated") or None,
            "cwe": record.get("cwe") or [], "description": record.get("description") or "",
            "references": record.get("references") or [],
            "url": f"{NVD_CVE}/{ident}" if nvd_status else f"{CVE_ORG}{ident}", "affects": {}}


def _candidate(record: dict, kev_dates: dict) -> dict:
    cvss = record.get("cvss") or {}
    severity = cvss.get("severity") if cvss.get("severity") in SEVERITIES else "UNKNOWN"
    return {"id": record["id"], "status": record["status"], "disputed": record["disputed"],
            "severity": severity, "cvss_score": cvss.get("score"), "cvss_vector": cvss.get("vector"),
            "cvss_source": cvss.get("source"),
            "kev_date_added": record.get("kev_date_added") or kev_dates.get(record["id"]),
            "published": record.get("published"), "modified": record.get("modified"), "cwe": record["cwe"],
            "description": record["description"], "references": record["references"],
            "url": f"{NVD_CVE}/{record['id']}", "affects": {}}
