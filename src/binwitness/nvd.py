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
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass

from binwitness.versions import compare
from binwitness.vulns import SEVERITIES

NVD_FEEDS = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_CVE = "https://nvd.nist.gov/vuln/detail"
FIRST_YEAR = 2002
# The four conditions for linking a CPE with a package, set on the NVD and OSV data of October 2026 (see
# Linker). Products that bundle a library (an appliance, a suite) are what they keep out.
PACKAGE_SHARE = 0.3
TOP_SHARE = 0.5
PRODUCT_SHARE = 0.5
PROJECT_SHARE = 0.25
# Enough to tell which module or language binding a record is about; Oracle's quarterly records list hundreds.
REFERENCES_KEPT = 20
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
_HUMP = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_LANGUAGES = {
    "Java": r"\bJava\b(?!\s*Script)|\bJVM\b|Connector/J\b",
    "Kotlin": r"\bKotlin\b", "Scala": r"\bScala\b", "Groovy": r"\bGroovy\b",
    "JavaScript": r"\bJavaScript\b|\bTypeScript\b",
    "Node.js": r"\bNode\.?js\b|Connector/Node\.js",
    "Go": r"\bGo\b|\bgolang\b", "C++": r"C\+\+", "C#": r"C#", ".NET": r"\.NET\b|Connector/NET\b",
    "C": r"\bc_glib\b|\bC/GLib\b|Connector/C\b(?!\+)|Connector/ODBC\b|\bC (?:client|cli|library|bindings?|API)\b",
    "Python": r"\bPython\b", "Ruby": r"\bRuby\b", "Rust": r"\bRust\b", "PHP": r"\bPHP\b", "Perl": r"\bPerl\b",
    "Haskell": r"\bHaskell\b", "Erlang": r"\bErlang\b", "Lua": r"\bLua\b", "Swift": r"\bSwift\b",
    "Dart": r"\bDart\b", "Delphi": r"\bDelphi\b",
}
_LANGUAGE_PATTERNS = {label: re.compile(pattern) for label, pattern in _LANGUAGES.items()}
# A package's own languages, and the ones that say nothing about a binding when named (a cross-site scripting
# record of a Java library speaks of JavaScript).
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


@dataclass(frozen=True)
class Naming:
    """What a record's description names: Maven modules, languages, Java classes, other CVEs. ``builds`` are
    artifactIds named with a build (bcpkix-fips) and no groupId: whose they are is up to the family at hand."""
    modules: tuple[str, ...]
    builds: tuple[str, ...]
    languages: tuple[str, ...]
    classes: tuple[str, ...]
    cves: frozenset

    @classmethod
    def of(cls, record: dict | None, is_class=None) -> "Naming":
        """``is_class``: whether a word is the simple name of a class in some jar at hand, which makes a
        two-word name (CertificatePinner) count; without it only longer names do."""
        text = (record or {}).get("description") or ""
        modules = tuple(dict.fromkeys(f"{g}:{a}" for g, a in _COORDINATE.findall(text)))
        builds = tuple(dict.fromkeys(a for a in _ARTIFACT.findall(text) if module_of(a) != a))
        languages = tuple(label for label, pattern in _LANGUAGE_PATTERNS.items() if pattern.search(text))
        qualified = list(dict.fromkeys(_QUALIFIED_CLASS.findall(text)))
        tails = {q.rsplit(".", 1)[1] for q in qualified}
        # A bare word counts when it reads as a class name (UrlFilenameViewController), or when it is one in a
        # jar at hand; WebFlux or GitHub could as well be a product or a concept.
        words = [w for w in dict.fromkeys(_WORD.findall(text)) if w not in tails and (
                 _humps(w) >= CLASS_WORD_HUMPS or _humps(w) == 2 and is_class is not None and is_class(w))]
        return cls(modules, builds, languages, tuple(qualified + words),
                   frozenset(_CVE.findall(text)) - {(record or {}).get("id")})

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
        named = set(self.languages) - NEUTRAL_LANGUAGES.get(ecosystem, set())
        own = OWN_LANGUAGES.get(ecosystem, set())
        return bool(named) and not named & own

    def placed(self, classes: set[str] | None) -> tuple[list[str] | None, list[str] | None]:
        """(named classes the jar holds, named classes it does not); None for both when its entries are
        unknown. A relocated (shaded) copy of a class counts as held, and the case of a name is not trusted."""
        if classes is None:
            return None, None
        # Records misspell the case now and then (UrlFileNameViewController).
        lowered = {e.lower() for e in classes}
        simple = {part for entry in lowered for part in entry.rsplit("/", 1)[-1][:-len(".class")].split("$")}
        held, missing = [], []
        for name in self.classes:
            if "." in name:
                path = name.replace(".", "/").lower() + ".class"
                inside = any(e == path or e.endswith("/" + path) for e in lowered)
            else:
                inside = name.lower() in simple
            # A two-word name missing from the jar says little: BigInteger is the JDK's, not this library's.
            if inside:
                held.append(name)
            elif "." in name or _humps(name) >= CLASS_WORD_HUMPS:
                missing.append(name)
        return held, missing


# ---- candidates -----------------------------------------------------------------------------------------

def attach(db, items: list[dict], vulnerabilities: dict, kev_dates: dict, datasets: dict[str, str],
           reason: str | None, listings=None) -> tuple[dict, dict, dict]:
    """(candidates by CVE id, links by purl, summary). ``datasets``: ecosystem -> its OSV dataset name;
    ``reason``: why candidates cannot be looked for at all, if so; ``listings``: the jar entries at hand, with
    ``of(item)`` (the class entries of the jar holding an item, None when unknown) and ``has_class(name)``."""
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

    held: dict[str, set | None] = {}

    def naming(ident: str) -> Naming:
        if ident not in namings:
            namings[ident] = Naming.of(linker.record(ident), listings.has_class if listings else None)
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

    def placed(ident: str, item: dict) -> tuple[list | None, list | None]:
        facts = naming(ident)
        if not facts.classes:
            return [], []
        if item["purl"] not in held:
            held[item["purl"]] = listings.of(item) if listings else None
        return facts.placed(held[item["purl"]])

    def hit_of(ident: str, cpe: str, ecosystem: str, version: str) -> Match | None:
        return next((m for m in map(match_of, (linker.record(ident) or {}).get("matches", []))
                     if m.cpe == cpe and m.covers(ecosystem, version)), None)

    def add(ident: str, item: dict, cpe: str, hit: Match, basis: str, single: bool):
        entry = table.get(ident) or table.setdefault(ident, _candidate(linker.record(ident), kev_dates))
        entry["affects"].setdefault(item["purl"], {"cpe": cpe, "versions": hit.describe(),
                                                   "conditional": hit.conditional, "basis": basis,
                                                   "single_cve_link": single})

    for item in items:
        ecosystem = item["ecosystem"]
        problem = db.cve_index_missing(datasets.get(ecosystem))
        if problem:
            not_checked[problem] += 1
            continue
        links = linker.links(ecosystem, item["name"])
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
                if modules:
                    named_modules.add((ident, cpe, ecosystem, home))
                    # An all-in-one jar that holds the named module's classes stays.
                    if not speaks_for(modules, item["name"]) and not placed(ident, item)[0]:
                        left_out["names_another_module"] += 1
                        continue
                add(ident, item, cpe, hit, "learned", link.single)
    # A record that names its module reaches that module, in any build, even where no CPE could be learned for
    # it (a module without CVEs of its own, or one inside an all-in-one jar), through the CPE learned for the
    # others.
    for ident, cpe, ecosystem, home in sorted(named_modules):
        for name in sorted(modules_named(ident, ecosystem, home)):
            for item in by_module.get((home, module_of(name.split(":", 1)[1])), []):
                if not item["version"] or item["purl"] in table.get(ident, {}).get("affects", {}) \
                        or ident in _own_ids(item, vulnerabilities):
                    continue
                hit = hit_of(ident, cpe, ecosystem, item["version"])
                if hit is not None:
                    add(ident, item, cpe, hit, "named", False)
    named = {item["purl"]: item for item in items}
    for ident, entry in table.items():
        facts = naming(ident)
        modules = sorted({m for (i, _), found in named_in.items() if i == ident for m in found} - set(facts.modules))
        entry["modules_named"], entry["languages_named"] = [*facts.modules, *modules], list(facts.languages)
        entry["classes_named"] = list(facts.classes)
        for ref, affected in entry["affects"].items():
            item = named[ref]
            affected["related_findings"] = _related(item, ident, facts, vulnerabilities, linker)
            affected["other_language_only"] = facts.other_language_only(item["ecosystem"])
            affected["classes_in_jar"], affected["classes_not_in_jar"] = placed(ident, item)
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
        },
        "pairs_reached_by_name": sum(1 for a in pairs if a["basis"] == "named"),
        "pairs_left_out": dict(left_out),
        "links_refused": {"version_ranges_apart": len(refused)},
        "components": {"with_link": linked, "without_link": without, "not_checked": sum(not_checked.values())},
        "components_not_checked_because": dict(not_checked),
        "nvd_records_without_cpe": db.nvd_without_cpe(),
        # An online scan's findings are as of the scan; its candidates are as of these copies.
        "data_as_of": {n: db.data_as_of(n) for n in ["nvd", *sorted(set(datasets.values()))] if db.has(n)},
    }
    return table, links_of, summary


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
