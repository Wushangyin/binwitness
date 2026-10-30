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
from collections.abc import Iterator
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
    packages: int = 0  # packages linked with the same CPE

    @property
    def single(self) -> bool:
        """Learned from one CVE only: the weakest link there is."""
        return self.project_shared == 1

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
    2. at least half of its CVEs that OSV attributes to any package belong to the package's project: a product
       that bundles libraries collects the CVEs of many projects;
    3. it is on at least a quarter of the project's CVEs: a bundling product that shipped one module of a large
       project can carry most of that module's few CVEs, never most of the project's.
    """

    def __init__(self, db):
        self.db = db
        self._links: dict[tuple[str, str], dict[str, Link]] = {}
        self._products: dict[str, tuple[list[str], dict[str, set]]] = {}
        self._projects: dict[tuple[str, str], tuple[Counter, int]] = {}

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
        own = project(ecosystem, name)
        found = {}
        for cpe, shared in sorted(counts.items()):
            if shared < PACKAGE_SHARE * total or shared < TOP_SHARE * top:
                continue
            ids, attributed = self.product(cpe)
            named = [c for c in ids if attributed.get(c)]
            same = sum(1 for c in named if any(e == ecosystem and project(e, n) == own for e, n in attributed[c]))
            if not named or same < PRODUCT_SHARE * len(named):
                continue
            in_project, project_total = self._project(ecosystem, own)
            if in_project[cpe] < PROJECT_SHARE * project_total:
                continue
            learned = sorted((c for c in cpes if cpe in cpes[c]), key=_cve_order)[-LEARNED_FROM_KEPT:]
            found[cpe] = Link(cpe, shared, total, same, len(named), in_project[cpe], project_total, learned[::-1])
        self._links[(ecosystem, name)] = found
        return found

    def packages(self, ecosystem: str, cpe: str) -> int:
        """How many packages the CPE is linked with: a product's CPE stands for all of its modules."""
        ids, attributed = self.product(cpe)
        names = sorted({n for c in ids for e, n in attributed.get(c, ()) if e == ecosystem})
        return sum(1 for n in names if cpe in self.links(ecosystem, n))


# ---- candidates -----------------------------------------------------------------------------------------

def attach(db, items: list[dict], vulnerabilities: dict, kev_dates: dict, datasets: dict[str, str],
           reason: str | None) -> tuple[dict, dict, dict]:
    """(candidates by CVE id, links by purl, summary). ``datasets``: ecosystem -> its OSV dataset name;
    ``reason``: why candidates cannot be looked for at all, if so."""
    if reason:
        return {}, {}, {"checked": False, "not_checked": reason}
    linker = Linker(db)
    records: dict[str, dict | None] = {}
    table, links_of = {}, {}
    linked = without = 0
    not_checked: Counter = Counter()
    packages: dict[tuple[str, str], int] = {}
    for item in items:
        ecosystem = item["ecosystem"]
        problem = db.cve_index_missing(datasets.get(ecosystem))
        if problem:
            not_checked[problem] += 1
            continue
        links = linker.links(ecosystem, item["name"])
        if not links or not item["version"]:
            without += 1
            continue
        linked += 1
        for link in links.values():
            if (ecosystem, link.cpe) not in packages:
                packages[(ecosystem, link.cpe)] = linker.packages(ecosystem, link.cpe)
            link.packages = packages[(ecosystem, link.cpe)]
        links_of[item["purl"]] = {cpe: link.as_dict() for cpe, link in links.items()}
        own = {a for k in item.get("vulnerabilities") or [] for a in [k, *vulnerabilities[k]["aliases"]]}
        for cpe, link in links.items():
            ids, attributed = linker.product(cpe)
            for ident in ids:
                if ident in own or attributed.get(ident):
                    continue
                if ident not in records:
                    records[ident] = db.nvd_record(ident)
                record = records[ident]
                hit = next((m for m in map(match_of, (record or {}).get("matches", []))
                            if m.cpe == cpe and m.covers(ecosystem, item["version"])), None)
                if hit is None:
                    continue
                entry = table.get(ident) or table.setdefault(ident, _candidate(record, kev_dates))
                entry["affects"].setdefault(item["purl"], {"cpe": cpe, "versions": hit.describe(),
                                                           "conditional": hit.conditional,
                                                           "single_cve_link": link.single})
    table = dict(sorted(table.items()))
    summary = {
        "checked": linked + without > 0, "not_checked": None if linked + without else
        "; ".join(not_checked) or "no components",
        "total": len(table),
        "pairs": sum(len(c["affects"]) for c in table.values()),
        "by_severity": {s: sum(1 for c in table.values() if c["severity"] == s) for s in SEVERITIES},
        "disputed": sum(1 for c in table.values() if c["disputed"]),
        "known_exploited": sum(1 for c in table.values() if c["kev_date_added"]),
        "only_from_single_cve_links": sum(1 for c in table.values()
                                          if all(a["single_cve_link"] for a in c["affects"].values())),
        "components": {"with_link": linked, "without_link": without, "not_checked": sum(not_checked.values())},
        "components_not_checked_because": dict(not_checked),
        "nvd_records_without_cpe": db.nvd_without_cpe(),
        # An online scan's findings are as of the scan; its candidates are as of these copies.
        "data_as_of": {n: db.data_as_of(n) for n in ["nvd", *sorted(set(datasets.values()))] if db.has(n)},
    }
    return table, links_of, summary


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
