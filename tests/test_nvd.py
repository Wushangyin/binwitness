"""NVD candidates: the feed reader, CPE matching, syncing the nvd dataset, learning which CPE names a package,
and how candidates reach a scan, its files and the MCP tools. All records are made up here."""
import csv
import gzip
import hashlib
import io
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from binwitness import localdb, nvd
from binwitness.crosscheck import crosscheck, load_other
from binwitness.localdb import LocalDb
from binwitness.mcp_server import Config, Refused, Service
from binwitness.net import Net
from binwitness.nvd import Match, matches, split_cpe
from binwitness.output import render_summary, write_all
from binwitness.scan import Options, scan

from helpers import ScriptedTransport, Served, make_zip
from test_localdb import fetcher, never, osv_zip
from test_scan import delivery, routes  # noqa: F401 (delivery is a fixture)

NOW = datetime.now(timezone.utc)
YEAR = NOW.year
# Within the days the modified feed covers, so that the next sync reads that feed rather than every year's.
RECENT = (NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000")
LATER = NOW.strftime("%Y-%m-%dT%H:%M:%S.000")


def cpe(vendor, product, version="*", target="*", vulnerable=True, part="a", **bounds):
    return {"vulnerable": vulnerable, "criteria": f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:{target}:*:*",
            **bounds}


def record(ident, *entries, status="Analyzed", platform=None, disputed=False, severity="HIGH",
           modified=RECENT, description=None):
    nodes = [{"operator": "OR", "negate": False, "cpeMatch": list(entries)}]
    if platform:
        nodes.append({"operator": "OR", "negate": False, "cpeMatch": [platform]})
    return {"id": ident, "vulnStatus": status, "published": "2025-06-01T00:00:00.000", "lastModified": modified,
            "cveTags": [{"sourceIdentifier": "cve@example.org", "tags": ["disputed"]}] if disputed else [],
            "descriptions": [{"lang": "en", "value": description or f"A flaw in {ident}."}],
            "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                           "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": severity,
                                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
            "weaknesses": [{"source": "nvd@nist.gov", "description": [{"lang": "en", "value": "CWE-502"}]}],
            "references": [{"url": f"https://example.org/{ident}"}, {"url": f"https://example.org/{ident}"}],
            "configurations": [{"operator": "AND" if platform else None, "nodes": nodes}] if entries else []}


def feed_text(*records):
    """As NVD publishes them: pretty-printed, with the array after a header."""
    return json.dumps({"resultsPerPage": len(records), "format": "NVD_CVE", "version": "2.0",
                       "timestamp": "2026-10-01T00:00:00.000",
                       "vulnerabilities": [{"cve": r} for r in records]}, indent=2)


def feed_routes(name, *records, digest=None):
    text = feed_text(*records).encode()
    meta = (f"lastModifiedDate:2026-10-01T03:00:01-04:00\r\nsize:{len(text)}\r\n"
            f"sha256:{digest or hashlib.sha256(text).hexdigest().upper()}\r\n")
    return {f"/{name}.meta": meta.encode(), f"/{name}.json.gz": Served(gzip.compress(text))}


def osv(osv_id, cve, name, ecosystem="Maven", withdrawn=None):
    entry = {"id": osv_id, "modified": "2026-01-01T00:00:00Z", "aliases": [cve],
             "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.5"}]}]}]}
    return {**entry, "withdrawn": withdrawn} if withdrawn else entry


# org.example:lib's own advisories carry example:lib in NVD; a product that bundles it (example:appliance)
# carries two of them as well, but mostly the CVEs of other projects.
OSV_RECORDS = [osv("GHSA-l1", "CVE-2024-0011", "org.example:lib"), osv("GHSA-l2", "CVE-2024-0012", "org.example:lib"),
               osv("GHSA-l3", "CVE-2024-0013", "org.example:lib"),
               osv("GHSA-o1", "CVE-2024-0101", "org.other:thing"), osv("GHSA-o2", "CVE-2024-0102", "org.other:thing"),
               osv("GHSA-o3", "CVE-2024-0103", "org.third:gadget"),
               osv("GHSA-s1", "CVE-2024-0301", "org.lonely:solo"),
               osv("GHSA-gone", "CVE-2024-0401", "org.lonely:solo", withdrawn="2026-01-02T00:00:00Z")]
NVD_RECORDS = [
    record("CVE-2024-0011", cpe("example", "lib", versionEndExcluding="0.5"), cpe("example", "appliance")),
    record("CVE-2024-0012", cpe("example", "lib", versionEndExcluding="0.5"), cpe("example", "appliance")),
    record("CVE-2024-0013", cpe("example", "lib", versionEndExcluding="0.5")),
    record("CVE-2024-0101", cpe("example", "appliance")), record("CVE-2024-0102", cpe("example", "appliance")),
    record("CVE-2024-0103", cpe("example", "appliance")),
    record("CVE-2024-0301", cpe("lonely", "solo")),
    # Unattributed: the candidates, and the records that must not become one.
    record("CVE-2023-0001", cpe("example", "lib", versionEndExcluding="1.1")),  # an online finding of the scan
    record("CVE-2025-0004", cpe("example", "lib", versionEndExcluding="2.0"), severity="CRITICAL"),
    record("CVE-2025-0005", cpe("example", "lib", "0.9")),
    record("CVE-2025-0006", cpe("example", "lib", target="node.js")),
    record("CVE-2025-0007", cpe("example", "lib"), platform=cpe("example", "os", part="o", vulnerable=False)),
    record("CVE-2025-0008", cpe("example", "lib", versionStartIncluding="1.0", versionEndIncluding="1.0"),
           disputed=True, severity="LOW"),
    record("CVE-2025-0009", cpe("example", "lib"), status="Rejected"),
    record("CVE-2025-0010", status="Awaiting Analysis"),
    record("CVE-2025-0011", status="Received"),
    record("CVE-2025-0201", cpe("example", "appliance", versionEndExcluding="5.0")),
    record("CVE-2025-0302", cpe("lonely", "solo", versionEndExcluding="3.0")),
    record("CVE-2025-0402", cpe("lonely", "solo", versionEndExcluding="3.0"),
           description="Solo before 3.0 lets a request through."),
]


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "FIRST_YEAR", YEAR)  # one yearly feed
    db = LocalDb(tmp_path / "db")
    transport = ScriptedTransport({"/Maven/all.zip": osv_zip(*OSV_RECORDS),
                                   **feed_routes(f"nvdcve-2.0-{YEAR}", *NVD_RECORDS)})
    outcomes = db.sync(["osv-maven", "nvd"], fetcher=fetcher(transport), log=lambda m: None)
    assert outcomes == {"osv-maven": f"downloaded {len(OSV_RECORDS)} records",
                        "nvd": f"downloaded {len(NVD_RECORDS) - 3} records with a CPE"}
    return LocalDb.open(tmp_path / "db")


def item(name, version="1.0", vulnerabilities=()):
    return {"ecosystem": "maven", "name": name, "version": version, "purl": f"pkg:maven/{name.replace(':', '/')}@{version}",
            "vulnerabilities": list(vulnerabilities)}


# A project (org.acme.web) with a subproject (org.acme.web.embed), an all-in-one jar (web-all), a module without
# CVEs of its own (web-socks), and a product that bundles it under its own release numbers (bundler:suite).
FAMILY_OSV = [osv("GHSA-w1", "CVE-2024-1001", "org.acme.web:web-core"), osv("GHSA-w2", "CVE-2024-1002", "org.acme.web:web-core"),
              osv("GHSA-w3", "CVE-2024-1003", "org.acme.web:web-core"),
              osv("GHSA-a1", "CVE-2024-1001", "org.acme.web:web-all"), osv("GHSA-a2", "CVE-2024-1002", "org.acme.web:web-all"),
              osv("GHSA-e3", "CVE-2024-1003", "org.acme.web.embed:web-embed")]
SUITE = cpe("bundler", "suite", versionStartIncluding="10.0", versionEndExcluding="10.5")
FAMILY_NVD = [
    *[record(f"CVE-2024-100{n}", cpe("acme", "web", versionEndExcluding="0.5"), SUITE) for n in (1, 2, 3)],
    record("CVE-2023-1201", cpe("acme", "proxy"), description="Acme Proxy mishandles headers, a variant of CVE-2025-1305."),
    record("CVE-2025-1301", cpe("acme", "web", versionEndExcluding="2.0"),
           description="In org.acme.web:web-socks before 2.0, SocksHandshakeDecoder reads past the buffer."),
    record("CVE-2025-1302", cpe("acme", "web", versionEndExcluding="2.0"), description="A copy of CVE-2023-1201 in Acme Web."),
    record("CVE-2025-1303", cpe("acme", "web", versionEndExcluding="2.0"), description="The Go client of Acme Web leaks tokens."),
    record("CVE-2025-1304", cpe("acme", "web", versionEndExcluding="2.0"),
           description="UrlFileNameViewController and CertPinner in Acme Web resolve any path."),
    record("CVE-2025-1305", cpe("acme", "web", versionEndExcluding="2.0"), description="Acme Web before 2.0 drops a header."),
]
FAMILY_ITEMS = [item("org.acme.web:web-core", vulnerabilities=["GHSA-f"]), item("org.acme.web:web-all"),
                item("org.acme.web.embed:web-embed"), item("org.acme.web:web-socks")]
FAMILY_FINDINGS = {"GHSA-f": {"aliases": ["CVE-2023-1201"]}}


class Listings:
    """The class entries of each package's jar; a package without any stands for a jar whose entries are unknown."""

    def __init__(self, entries):
        self.entries = entries

    def of(self, found):
        return self.entries.get(found["name"])

    def has_class(self, name):
        return any(e.rsplit("/", 1)[-1] == f"{name}.class" for entries in self.entries.values() for e in entries)


FAMILY_LISTINGS = Listings({
    "org.acme.web:web-core": {"org/acme/web/core/Server.class"},
    "org.acme.web:web-all": {"org/acme/web/core/Server.class", "org/acme/web/socks/SocksHandshakeDecoder.class",
                             "org/acme/web/servlet/UrlFilenameViewController.class", "org/acme/web/tls/CertPinner.class"},
    "org.acme.web:web-socks": {"org/acme/web/socks/SocksHandshakeDecoder.class"},
})


@pytest.fixture
def family_world(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "FIRST_YEAR", YEAR)
    db = LocalDb(tmp_path / "family")
    transport = ScriptedTransport({"/Maven/all.zip": osv_zip(*FAMILY_OSV),
                                   **feed_routes(f"nvdcve-2.0-{YEAR}", *FAMILY_NVD)})
    db.sync(["osv-maven", "nvd"], fetcher=fetcher(transport), log=lambda m: None)
    return LocalDb.open(tmp_path / "family")


# ---- feed and CPE ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("chunk", [1, 7, 64, 1 << 20])
def test_feed_items_decodes_a_pretty_printed_feed_entry_by_entry(chunk):
    text = feed_text(*NVD_RECORDS).encode()
    stream = io.BytesIO(text)
    assert [r["id"] for r in nvd.feed_items(stream, chunk)] == [r["id"] for r in NVD_RECORDS]
    assert stream.tell() == len(text)  # read to the end, for the digest
    assert not stream.closed  # the caller's stream, which takes the digest, stays usable


def test_feed_items_refuses_what_is_not_a_whole_feed():
    text = feed_text(*NVD_RECORDS)
    with pytest.raises(ValueError, match="ends inside an entry"):
        list(nvd.feed_items(io.BytesIO(text[:len(text) // 2].encode()), 64))
    with pytest.raises(ValueError, match="no vulnerabilities array"):
        list(nvd.feed_items(io.BytesIO(b'{"format": "NVD_CVE", "items": []}'), 8))


def test_split_cpe_unescapes_the_fields():
    fields = split_cpe(r"cpe:2.3:a:oracle:mysql_connector\/j:8.0.0:*:*:*:*:*:*:*")
    assert fields[3:6] == ["oracle", "mysql_connector/j", "8.0.0"] and len(fields) == 13


@pytest.mark.parametrize("match, version, covered, described", [
    (Match("v", "p", "*", "*", "*", end_excluding="2.0"), "1.9", True, "< 2.0"),
    (Match("v", "p", "*", "*", "*", end_excluding="2.0"), "2.0", False, "< 2.0"),
    (Match("v", "p", "*", "*", "*", start_including="1.0", end_including="1.4"), "1.4", True, ">= 1.0, <= 1.4"),
    (Match("v", "p", "*", "*", "*", start_excluding="1.0"), "1.0", False, "> 1.0"),
    (Match("v", "p", "1.2", "*", "*"), "1.2", True, "1.2"),
    (Match("v", "p", "1.2", "beta1", "*"), "1.2-beta1", True, "1.2 beta1"),
    (Match("v", "p", "-", "*", "*"), "1.2", False, "-"),
    (Match("v", "p", "*", "*", "node.js"), "1.2", False, "all versions (node.js)"),
    (Match("v", "p", "*", "*", "java"), "1.2", True, "all versions (java)"),
])
def test_cpe_match_covers_versions(match, version, covered, described):
    assert match.covers("maven", version) is covered
    assert match.describe() == described


def test_matches_keeps_vulnerable_applications_and_marks_platform_configurations():
    found = matches(record("CVE-1", cpe("v", "app"), cpe("v", "firmware", part="o"),
                           platform=cpe("v", "os", part="o", vulnerable=False)))
    assert [(m.cpe, m.conditional) for m in found] == [("v:app", True)]
    assert [m.cpe for m in matches(record("CVE-2", cpe("v", "app"), cpe("v", "app"), cpe("v", "lib")))] == ["v:app", "v:lib"]


def test_project_of_a_package():
    assert nvd.project("maven", "org.example:lib") == "org.example:"
    assert nvd.project("npm", "@scope/name") == "@scope/"
    assert nvd.project("npm", "left-pad") == "left-pad"
    assert nvd.family("maven", "org.acme.web.embed:web-embed") == nvd.family("maven", "org.acme.web:web-core") == \
        "org.acme.web:"
    assert nvd.family("maven", "org.example:lib") == "org.example:" and nvd.family("npm", "@scope/name") == "@scope/"


def interval(end, start="0"):
    return [(start, end, False)]


@pytest.mark.parametrize("intervals, listed, found, meet", [
    # The same fix, however each side spells it.
    (interval("4.1.125.Final"), set(), [Match("v", "p", "*", "*", "*", end_excluding="4.1.125")], True),
    (interval("2.0"), set(), [Match("v", "p", "*", "*", "*", start_including="1.5", end_excluding="2.5")], True),
    ([], {"1.2", "1.3"}, [Match("v", "p", "1.3", "*", "*")], True),
    (interval("1.4", start="1.0"), set(), [Match("v", "p", "*", "*", "*")], True),  # NVD gives every version
    # A product that bundles the package numbers its own releases.
    (interval("2.0"), set(), [Match("v", "p", "*", "*", "*", start_including="10.0", end_excluding="10.5")], False),
    (interval("2.0"), set(), [Match("v", "p", "*", "*", "*", end_excluding="12.2.0.1.22")], False),
    # Two ranges open at the bottom with different fixes share only the early versions every range covers.
    (interval("2.0"), set(), [Match("v", "p", "*", "*", "*", end_excluding="3.1")], False),
    (interval("2.0"), set(), [Match("v", "p", "-", "*", "*")], None),
    ([], set(), [Match("v", "p", "*", "*", "*", end_excluding="2.0")], None),
])
def test_ranges_meet(intervals, listed, found, meet):
    assert nvd.ranges_meet("maven", intervals, listed, found) is meet


def test_naming_reads_the_modules_classes_languages_and_cves_a_record_names():
    text = ("In org.acme.web:web-socks before 2.0, SocksHandshakeDecoder and org.acme.web.socks.Frame let a peer read "
            "memory; CertPinner and WebFlux are not affected. The C client is affected as well, as in CVE-2024-9999.")
    facts = nvd.Naming.of({"id": "CVE-2025-0001", "description": text}, is_class={"CertPinner"}.__contains__)
    assert facts.modules == ("org.acme.web:web-socks",)
    # A two-word name is a class only when some jar at hand has one by that name: WebFlux could be a product.
    assert facts.classes == ("org.acme.web.socks.Frame", "SocksHandshakeDecoder", "CertPinner")
    assert "CertPinner" not in nvd.Naming.of({"description": text}).classes
    assert facts.languages == ("C",) and facts.cves == {"CVE-2024-9999"}
    assert facts.modules_of("maven", "org.acme.web:") == {"org.acme.web:web-socks"}
    assert facts.modules_of("maven", "org.example:") == set()


def test_a_build_named_without_its_group_is_read_as_its_module():
    assert [nvd.module_of(a) for a in ("acpkix-jdk18on", "acpkix-fips", "acprov-jdk15to18", "acprov-lts8on",
                                       "acprov-ext-jdk15on", "acmail-jdk14", "web-core")] == \
        ["acpkix", "acpkix", "acprov", "acprov", "acprov-ext", "acmail", "web-core"]
    facts = nvd.Naming.of({"description": "Acme Crypto FIPS before acpkix-fips 1.0.12 (1.0.X series), like the "
                                          "x-forwarded-for header and org.acme.crypto:acmail-jdk14, is affected."})
    # A word without a build (x-forwarded-for) is not a module; a coordinate is one already.
    assert facts.builds == ("acpkix-fips",) and facts.modules == ("org.acme.crypto:acmail-jdk14",)
    groups = {"acpkix-fips": "org.acme.crypto"}.get
    assert facts.modules_of("maven", "org.acme.crypto:", groups) == {"org.acme.crypto:acmail-jdk14",
                                                                     "org.acme.crypto:acpkix-fips"}
    assert facts.modules_of("maven", "org.acme.crypto:") == {"org.acme.crypto:acmail-jdk14"}
    # A build of the package's module speaks for it, and so does a module its name begins with: the
    # provider of a FIPS edition (ac-fips) is acprov's counterpart.
    prov = "org.acme.crypto:acprov-jdk18on"
    assert nvd.speaks_for({"org.acme.crypto:acprov-fips"}, prov) and nvd.speaks_for({"org.acme.crypto:ac-fips"}, prov)
    assert not nvd.speaks_for({"org.acme.crypto:acpkix-fips"}, prov)


@pytest.mark.parametrize("text, ecosystem, other", [
    ("The Go client leaks tokens.", "maven", True),
    ("The Go and Java clients leak tokens.", "maven", False),
    ("Cross-site scripting: injected JavaScript runs in the console.", "maven", False),
    ("The Java client leaks tokens.", "npm", True),
    ("A flaw.", "maven", False),
])
def test_a_record_that_names_only_another_language(text, ecosystem, other):
    assert nvd.Naming.of({"description": text}).other_language_only(ecosystem) is other


def test_named_classes_are_found_in_a_jar_whatever_their_case_or_relocation():
    facts = nvd.Naming.of({"description": "UrlFileNameViewController, org.acme.web.socks.Frame, CertPinner and "
                                          "PathPatternParserHelper resolve any path."}, is_class=lambda word: True)
    entries = {"org/acme/web/servlet/UrlFilenameViewController.class", "shaded/org/acme/web/socks/Frame.class",
               "org/acme/web/Server$Inner.class"}
    # A two-word name missing from the jar says little (BigInteger is the JDK's), so it is not listed missing.
    assert facts.placed(entries) == (["org.acme.web.socks.Frame", "UrlFileNameViewController"],
                                     ["PathPatternParserHelper"])
    assert facts.placed(None) == (None, None)


# ---- syncing ------------------------------------------------------------------------------------------

def test_nvd_sync_leaves_out_rejected_records_and_counts_those_without_a_cpe(world):
    assert world.nvd_record("CVE-2025-0009") is None
    assert world.nvd_without_cpe() == {"Awaiting Analysis": 1, "Received": 1}
    stored = world.nvd_record("CVE-2025-0004")
    assert stored["references"] == ["https://example.org/CVE-2025-0004"]  # deduplicated
    assert stored["cvss"]["severity"] == "CRITICAL" and stored["cwe"] == ["CWE-502"]
    assert world.nvd_ids("example:lib")[:2] == ["CVE-2023-0001", "CVE-2024-0011"]
    assert world.state["nvd"]["records"] == len(NVD_RECORDS) - 3


def test_nvd_sync_updates_from_the_modified_feed_then_is_up_to_date(world):
    changed = [record("CVE-2025-0004", cpe("example", "lib", versionEndExcluding="0.8")),
               record("CVE-2025-0008", cpe("example", "lib"), status="Rejected"),
               record("CVE-2026-0001", cpe("example", "lib"), modified=LATER)]
    modified = feed_routes("nvdcve-2.0-modified", *changed)
    db = LocalDb(world.directory)
    outcome = db.sync(["nvd"], fetcher=fetcher(ScriptedTransport({**modified, f"nvdcve-2.0-{YEAR}": never})),
                      log=lambda m: None)
    assert outcome == {"nvd": "updated: 2 records with a CPE written, 2 replaced or removed"}
    db = LocalDb.open(world.directory)
    assert db.nvd_record("CVE-2025-0008") is None
    assert [m["end_excluding"] for m in db.nvd_record("CVE-2025-0004")["matches"]] == ["0.8"]
    assert "CVE-2026-0001" in db.nvd_ids("example:lib")
    assert db.state["nvd"]["data_as_of"].startswith(LATER[:19])
    again = ScriptedTransport({"/nvdcve-2.0-modified.meta": modified["/nvdcve-2.0-modified.meta"], "": never})
    assert LocalDb(world.directory).sync(["nvd"], fetcher=fetcher(again), log=lambda m: None) == {"nvd": "up to date"}


def test_nvd_feed_that_does_not_match_its_digest_is_fetched_again_then_refused(world):
    good = feed_routes("nvdcve-2.0-modified", record("CVE-2026-0002", cpe("example", "lib")))
    stale = feed_routes("nvdcve-2.0-modified", record("CVE-2026-0003", cpe("example", "lib")))
    served = iter([stale["/nvdcve-2.0-modified.json.gz"], good["/nvdcve-2.0-modified.json.gz"]])
    transport = ScriptedTransport({"/nvdcve-2.0-modified.meta": good["/nvdcve-2.0-modified.meta"],
                                   "/nvdcve-2.0-modified.json.gz": lambda m, u, b: bytes(next(served))})
    outcome = LocalDb(world.directory).sync(["nvd"], fetcher=fetcher(transport), log=lambda m: None)
    assert outcome == {"nvd": "updated: 1 record with a CPE written, 0 replaced or removed"}
    assert LocalDb.open(world.directory).nvd_record("CVE-2026-0003") is None

    before = dict(LocalDb(world.directory).state["nvd"])
    wrong = feed_routes("nvdcve-2.0-modified", record("CVE-2026-0004", cpe("example", "lib")), digest="00" * 32)
    outcome = LocalDb(world.directory).sync(["nvd"], fetcher=fetcher(ScriptedTransport(wrong)), log=lambda m: None)
    assert outcome["nvd"].startswith("failed") and "does not match the digest" in outcome["nvd"]
    db = LocalDb.open(world.directory)
    assert db.state["nvd"] == before and db.nvd_record("CVE-2026-0004") is None


def test_osv_copy_from_before_the_cve_index_gets_it_at_the_next_sync(world):
    path = world.path("osv-maven")
    world.close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("DROP TABLE cves")
        connection.commit()
    old = LocalDb.open(world.directory)
    assert "predates the CVE index" in old.cve_index_missing("osv-maven")
    table, _, summary = nvd.attach(old, [item("org.example:lib")], {}, {}, {"maven": "osv-maven"}, None)
    assert table == {} and summary["checked"] is False and "predates the CVE index" in summary["not_checked"]
    old.close()
    transport = ScriptedTransport({"/Maven/modified_id.csv": Served(b""), "": never})
    LocalDb(world.directory).sync(["osv-maven"], fetcher=fetcher(transport), log=lambda m: None)
    migrated = LocalDb.open(world.directory)
    assert migrated.cve_index_missing("osv-maven") is None
    assert migrated.osv_cves("maven", "org.example:lib") == {"CVE-2024-0011", "CVE-2024-0012", "CVE-2024-0013"}


# ---- learning and candidates -------------------------------------------------------------------------

def test_a_cpe_is_linked_from_attributed_cves_and_bundling_products_are_not(world):
    linker = nvd.Linker(world)
    links = linker.links("maven", "org.example:lib")
    # example:appliance is on two of lib's three CVEs, but most of its attributed CVEs are of other projects.
    assert list(links) == ["example:lib"]
    link = links["example:lib"]
    assert (link.shared, link.package_cves, link.product_same_project, link.product_attributed,
            link.project_shared, link.project_cves) == (3, 3, 3, 3, 3, 3)
    assert link.learned_from == ["CVE-2024-0013", "CVE-2024-0012", "CVE-2024-0011"] and not link.single
    # The withdrawn advisory does not teach a link, so solo's rests on one CVE.
    assert linker.links("maven", "org.lonely:solo")["lonely:solo"].single
    assert linker.links("maven", "org.example:plain") == {}


def test_candidates_are_the_unattributed_records_of_a_linked_cpe_that_cover_the_version(world):
    items = [item("org.example:lib", vulnerabilities=["GHSA-online"]), item("org.lonely:solo"),
             item("org.example:plain"), item("org.example:lib", version="")]
    vulnerabilities = {"GHSA-online": {"aliases": ["CVE-2023-0001"]}}
    table, links, summary = nvd.attach(world, items, vulnerabilities, {"CVE-2025-0004": "2025-07-01"},
                                       {"maven": "osv-maven"}, None)
    # Not: the scan's own finding (0001), the attributed ones (0011-0013), another version (0005), a Node.js
    # package (0006), the rejected one (0009), the bundling product's (0201); and the withdrawn GHSA-gone still
    # attributes CVE-2024-0401, which is no candidate either.
    assert list(table) == ["CVE-2025-0004", "CVE-2025-0007", "CVE-2025-0008", "CVE-2025-0302", "CVE-2025-0402"]
    lib = "pkg:maven/org.example/lib@1.0"
    assert table["CVE-2025-0004"]["affects"] == {lib: {
        "cpe": "example:lib", "versions": "< 2.0", "conditional": False, "basis": "learned", "single_cve_link": False,
        "related_findings": [], "other_language_only": False, "classes_in_jar": [], "classes_not_in_jar": []}}
    assert table["CVE-2025-0004"]["kev_date_added"] == "2025-07-01"
    assert table["CVE-2025-0007"]["affects"][lib]["conditional"] is True
    assert table["CVE-2025-0008"]["disputed"] is True and table["CVE-2025-0008"]["severity"] == "LOW"
    assert table["CVE-2025-0302"]["affects"]["pkg:maven/org.lonely/solo@1.0"]["single_cve_link"] is True
    assert links[lib]["example:lib"]["packages"] == 1
    assert summary["components"] == {"with_link": 2, "without_link": 2, "not_checked": 0}
    assert summary["by_severity"] == {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 0}
    assert (summary["disputed"], summary["known_exploited"], summary["only_from_single_cve_links"]) == (1, 1, 2)
    assert summary["nvd_records_without_cpe"] == {"Awaiting Analysis": 1, "Received": 1}
    assert set(summary["data_as_of"]) == {"nvd", "osv-maven"}


def test_no_candidates_without_the_datasets(world, tmp_path):
    table, links, summary = nvd.attach(world, [item("org.example:lib")], {}, {}, {}, None)
    assert table == {} and summary["checked"] is False
    assert summary["not_checked"] == "the local OSV dataset is not installed (binwitness db sync vulns)"
    assert nvd.attach(world, [], {}, {}, {}, "turned off")[2] == {"checked": False, "not_checked": "turned off"}


def test_a_subproject_learns_its_projects_cpe_and_a_product_numbered_otherwise_is_refused(family_world):
    linker = nvd.Linker(family_world)
    # None of acme:web's attributed CVEs is of web-embed's own groupId; all of them are of its family.
    embed = linker.links("maven", "org.acme.web.embed:web-embed")
    assert list(embed) == ["acme:web"] and embed["acme:web"].single
    core = linker.links("maven", "org.acme.web:web-core")
    assert list(core) == ["acme:web"] and (core["acme:web"].ranges_meet, core["acme:web"].ranges_apart) == (3, 0)
    # bundler:suite is on every CVE of the project, but no version of the package is in its 10.x releases.
    assert linker.apart("maven", "org.acme.web:web-core") == ["bundler:suite"]


def test_candidates_carry_what_their_records_name(family_world):
    table, links, summary = nvd.attach(family_world, FAMILY_ITEMS, FAMILY_FINDINGS, {}, {"maven": "osv-maven"}, None,
                                       FAMILY_LISTINGS)
    core, everything, embed, socks = (i["purl"] for i in FAMILY_ITEMS)
    assert list(table) == ["CVE-2025-1301", "CVE-2025-1302", "CVE-2025-1303", "CVE-2025-1304", "CVE-2025-1305"]
    # Named for web-socks, which has no CVEs to learn a CPE from: it reaches web-socks by name, and of the others
    # only the all-in-one jar that holds the named class.
    named = table["CVE-2025-1301"]
    assert named["modules_named"] == ["org.acme.web:web-socks"] and named["classes_named"] == ["SocksHandshakeDecoder"]
    assert {ref: (a["basis"], a["classes_in_jar"]) for ref, a in named["affects"].items()} == {
        everything: ("learned", ["SocksHandshakeDecoder"]), socks: ("named", ["SocksHandshakeDecoder"])}
    assert table["CVE-2025-1302"]["affects"][core]["related_findings"] == ["GHSA-f"]  # its text names the finding
    assert table["CVE-2025-1305"]["affects"][core]["related_findings"] == ["GHSA-f"]  # the finding's names it
    assert table["CVE-2025-1302"]["affects"][everything]["related_findings"] == []
    assert table["CVE-2025-1303"]["languages_named"] == ["Go"]
    assert all(a["other_language_only"] for a in table["CVE-2025-1303"]["affects"].values())
    classes = {ref: (a["classes_in_jar"], a["classes_not_in_jar"]) for ref, a in table["CVE-2025-1304"]["affects"].items()}
    assert classes == {core: ([], ["UrlFileNameViewController"]),
                       everything: (["UrlFileNameViewController", "CertPinner"], []), embed: (None, None)}
    assert summary["pairs"] == 14 and summary["components"]["with_link"] == 3
    assert summary["pairs_flagged"] == {"same_flaw_as_a_finding": 2, "other_language_only": 3,
                                        "named_classes_not_in_jar": 1}
    assert summary["pairs_reached_by_name"] == 1 and summary["pairs_left_out"] == {"names_another_module": 2}
    assert summary["links_refused"] == {"version_ranges_apart": 3}
    assert "bundler:suite" not in links[core]


# A library published in builds (acprov-jdk18on, acpkix-jdk15on) and in a FIPS edition whose modules OSV knows
# (acpkix-fips, ac-fips), all under one CPE. Its records name the FIPS module the flaw is in.
CRYPTO_OSV = [*[osv(f"GHSA-c{n}", f"CVE-2024-200{n}", "org.acme.crypto:acprov-jdk18on") for n in (1, 2, 3)],
              osv("GHSA-c4", "CVE-2024-2004", "org.acme.crypto:acpkix-fips"),
              osv("GHSA-c5", "CVE-2024-2005", "org.acme.crypto:ac-fips")]
CRYPTO_NVD = [
    *[record(f"CVE-2024-200{n}", cpe("acme", "crypto", versionEndExcluding="0.5")) for n in (1, 2, 3)],
    *[record(ident, cpe("acme", "crypto", versionEndExcluding="2.0"),
             description=f"{what} in Acme Crypto before 2.0. This also affects Acme Crypto FIPS before {module} 1.0.12.")
      for ident, what, module in [("CVE-2025-2101", "CMS SignedData without signers verifies", "acpkix-fips"),
                                  ("CVE-2025-2102", "A weak key is accepted", "ac-fips"),
                                  ("CVE-2025-2103", "An S/MIME part is not bound", "acmail-fips"),
                                  ("CVE-2025-2104", "OER decoding overflows", "acutil-fips"),
                                  ("CVE-2025-2105", "AuthEnvelopedData skips the tag length", "acpkix-fips")]],
]
CRYPTO_ITEMS = [item("org.acme.crypto:acprov-jdk18on"), item("org.acme.crypto:acpkix-jdk15on"),
                item("org.acme.crypto:acmail-jdk14")]
CRYPTO_LISTINGS = Listings({
    "org.acme.crypto:acprov-jdk18on": {"org/acme/crypto/asn1/cms/AuthEnvelopedData.class"},
    "org.acme.crypto:acpkix-jdk15on": {"org/acme/crypto/cms/CMSSignedData.class"},
})


@pytest.fixture
def crypto_world(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "FIRST_YEAR", YEAR)
    db = LocalDb(tmp_path / "crypto")
    transport = ScriptedTransport({"/Maven/all.zip": osv_zip(*CRYPTO_OSV),
                                   **feed_routes(f"nvdcve-2.0-{YEAR}", *CRYPTO_NVD)})
    db.sync(["osv-maven", "nvd"], fetcher=fetcher(transport), log=lambda m: None)
    return LocalDb.open(tmp_path / "crypto")


def test_a_record_naming_another_build_of_a_module_goes_to_that_module(crypto_world, monkeypatch):
    assert nvd.Linker(crypto_world).modules("org.acme.crypto:") == {
        "ac-fips": "org.acme.crypto", "acpkix-fips": "org.acme.crypto", "acprov-jdk18on": "org.acme.crypto"}
    prov, pkix, mail = (i["purl"] for i in CRYPTO_ITEMS)

    def attached():
        table, _, summary = nvd.attach(crypto_world, CRYPTO_ITEMS, {}, {}, {"maven": "osv-maven"}, None,
                                       CRYPTO_LISTINGS)
        return {ident: {ref: a["basis"] for ref, a in c["affects"].items()} for ident, c in table.items()}, \
            {ident: c["modules_named"] for ident, c in table.items()}, summary

    affects, named, summary = attached()
    # acpkix-fips is OSV's, acmail-fips is known as a build of the acmail jar at hand; their records leave the
    # provider for the module's builds at hand, which no CPE was learned for. One whose named class the
    # provider's jar holds stays on it. ac-fips is the provider's counterpart; acutil-fips is no module known.
    assert affects == {"CVE-2025-2101": {pkix: "named"}, "CVE-2025-2102": {prov: "learned"},
                       "CVE-2025-2103": {mail: "named"}, "CVE-2025-2104": {prov: "learned"},
                       "CVE-2025-2105": {prov: "learned", pkix: "named"}}
    assert named == {"CVE-2025-2101": ["org.acme.crypto:acpkix-fips"], "CVE-2025-2102": ["org.acme.crypto:ac-fips"],
                     "CVE-2025-2103": ["org.acme.crypto:acmail-fips"], "CVE-2025-2104": [],
                     "CVE-2025-2105": ["org.acme.crypto:acpkix-fips"]}
    assert summary["pairs_left_out"] == {"names_another_module": 2} and summary["pairs_reached_by_name"] == 3

    # The hash index of Maven Central knows the rest, of this family or of another.
    index = {"acutil-fips": ["org.acme.crypto"]}
    monkeypatch.setattr(crypto_world, "maven_groups", lambda artifact: index.get(artifact, []))
    affects, named, summary = attached()
    assert "CVE-2025-2104" not in affects and summary["pairs_left_out"] == {"names_another_module": 3}
    index["acutil-fips"] = ["org.other.crypto"]
    assert attached()[0]["CVE-2025-2104"] == {prov: "learned"}


# ---- scans, files, MCP ------------------------------------------------------------------------------------

def online_scan(tmp_path, delivery, candidates_db, **options):  # noqa: F811
    net = Net(cache_dir=tmp_path / "cache", transport=ScriptedTransport(routes()), sleep=lambda s: None)
    return scan([delivery], net, Options(first_party_groups=("com.acme",), scan_js=False, **options),
                log=lambda m: None, candidates_db=candidates_db)


def test_an_online_scan_has_candidates_apart_from_its_findings(tmp_path, delivery, world):  # noqa: F811
    result = online_scan(tmp_path, delivery, world)
    lib = next(c for c in result["components"] if c["name"] == "org.example:lib")
    assert lib["vulnerabilities"] == ["CVE-2023-0001"]  # from the online lookup; not a candidate as well
    assert list(result["candidates"]) == ["CVE-2025-0004", "CVE-2025-0007", "CVE-2025-0008"]
    assert result["summary"]["vulnerabilities"]["total"] == len(result["vulnerabilities"])
    assert "CVE-2025-0004" not in result["vulnerabilities"]
    assert set(result["candidate_links"]) == {lib["purl"]}
    out = tmp_path / "out"
    write_all(result, out)
    assert "CVE-2025-0004" not in (out / "sbom.cdx.json").read_text("utf-8")
    assert "CVE-2025-0004" not in (out / "vulnerabilities.csv").read_text("utf-8")
    rows = list(csv.DictReader((out / "candidates.csv").open(encoding="utf-8-sig")))
    assert [(r["id"], r["component"], r["affected versions (NVD)"]) for r in rows][0] == (
        "CVE-2025-0004", lib["purl"], "< 2.0")
    assert rows[0]["link learned from"] == "CVE-2024-0013 CVE-2024-0012 CVE-2024-0011"
    assert rows[0]["data as of"].startswith("nvd ") and "osv-maven " in rows[0]["data as of"]
    text = render_summary(result)
    assert "candidates   3 NVD records not attributed to a package in the local OSV data, not counted above" in text
    assert "NVD has given no CPE yet to 2 records (local nvd of " in text


@pytest.mark.parametrize("why, options, expected", [
    ("no nvd dataset", {}, "the nvd dataset is not installed (binwitness db sync nvd vulns)"),
    ("no vulnerability lookup", {"vulnerabilities": False}, "the vulnerability lookup was turned off (--no-vulns)"),
])
def test_a_scan_says_when_candidates_were_not_looked_for(tmp_path, delivery, why, options, expected):  # noqa: F811
    result = online_scan(tmp_path, delivery, None, **options)
    assert result["candidates"] == {} and result["summary"]["candidates"]["checked"] is False
    assert expected in result["summary"]["candidates"]["not_checked"]
    out = tmp_path / "out"
    write_all(result, out)
    rows = list(csv.reader((out / "candidates.csv").open(encoding="utf-8-sig")))
    # Never an empty table, which reads as none.
    assert rows[1][0] == "not checked" and expected in rows[1][rows[0].index("description")]
    if options.get("vulnerabilities", True):
        assert f"candidates   not checked: " in render_summary(result)


def test_crosscheck_marks_the_other_tools_findings_that_are_candidates(tmp_path, delivery, world):  # noqa: F811
    result = online_scan(tmp_path, delivery, world)
    other = tmp_path / "other.csv"
    other.write_text("component,version,vulnerability\norg.example:lib,1.0,CVE-2025-0004\n"
                     "org.example:lib,1.0,CVE-2099-0001\n", "utf-8")
    github = Net(cache_dir=tmp_path / "gh", transport=ScriptedTransport({"api.github.com": [], "api.osv.dev": {}}),
                 sleep=lambda s: None)
    report = crosscheck(result, load_other(str(other)), github)
    marked = {x["id"]: x["candidate_cpe"] for x in report["only_theirs"]}
    assert marked == {"CVE-2025-0004": "example:lib", "CVE-2099-0001": None}
    assert sum(report["summary"]["only_theirs_among_candidates"].values()) == 1
    assert report["summary"]["candidates_checked"] is True


def test_mcp_lists_candidates_and_gives_what_to_check(tmp_path, delivery, world):  # noqa: F811
    result = online_scan(tmp_path, delivery, world)
    write_all(result, tmp_path / "out")
    service = Service(Config(results=tmp_path / "results", lookup="local"),
                      net=Net(cache_dir=tmp_path / "c", offline=True, transport=ScriptedTransport({"": never})))
    scan_id = service.open_result(str(tmp_path / "out"))["scan_id"]
    assert service.overview(scan_id)["candidates"]["total"] == 3
    assert "3 NVD candidates" in service.overview(scan_id)["coverage"]["candidates"]
    listed = service.list_candidates(scan_id, min_severity="high")
    assert [c["id"] for c in listed["candidates"]] == ["CVE-2025-0004", "CVE-2025-0007"]
    assert "not findings" in listed["note"]
    assert [c["id"] for c in service.list_candidates(scan_id, include_disputed=False)["candidates"]] == [
        "CVE-2025-0004", "CVE-2025-0007"]
    assert service.list_candidates(scan_id, text="nothing-like-it")["total"] == 0
    detail = service.get_candidate(scan_id, "cve-2025-0004")
    affected = detail["affects"][0]
    assert affected["versions"] == "< 2.0" and affected["findings_of_the_component"] == 1
    assert affected["link"] == "org.example:lib -> example:lib" and affected["flags"] == []
    [link] = detail["links"]
    assert link["learned_from"] == ["CVE-2024-0013", "CVE-2024-0012", "CVE-2024-0011"]
    assert "3 of the 3 CVEs OSV attributes to org.example:lib" in link["meaning"]
    assert "NVD's versions overlap OSV's on 3 of the 3 CVEs" in link["meaning"]
    assert detail["candidate"]["references"] == ["https://example.org/CVE-2025-0004"]
    assert any("first pass" in line for line in detail["judging"])
    component = service.get_component(scan_id, "org.example:lib")["component"]
    assert [c["id"] for c in component["candidates"]] == ["CVE-2025-0004", "CVE-2025-0007", "CVE-2025-0008"]
    with pytest.raises(Refused, match="a finding of this scan, not a candidate; get_vulnerability"):
        service.get_candidate(scan_id, "CVE-2023-0001")
    with pytest.raises(Refused, match="an NVD candidate of this scan; get_candidate"):
        service.get_vulnerability(scan_id, "CVE-2025-0004")


def test_mcp_on_a_result_from_before_candidates(tmp_path, delivery, world):  # noqa: F811
    result = online_scan(tmp_path, delivery, world)
    for key in ("candidates", "candidate_links"):
        del result[key]
    del result["summary"]["candidates"]
    result["tool"]["version"] = "0.3.2"
    out = tmp_path / "old"
    out.mkdir()
    (out / "binwitness.json").write_text(json.dumps(result), "utf-8")
    service = Service(Config(results=tmp_path / "results", lookup="local"),
                      net=Net(cache_dir=tmp_path / "c", offline=True, transport=ScriptedTransport({"": never})))
    scan_id = service.open_result(str(out))["scan_id"]
    state = service.list_candidates(scan_id)["candidates"]
    assert state["checked"] is False and "binwitness 0.3.2, before candidates existed" in state["not_checked"]
    with pytest.raises(Refused, match="candidates were not looked for"):
        service.get_candidate(scan_id, "CVE-2025-0004")
    assert "candidates" not in service.get_component(scan_id, "org.example:lib")["component"]
    assert render_summary(result).count("candidates") == 0


def test_flags_reach_the_files_and_the_mcp_tools(tmp_path, delivery, world, family_world):  # noqa: F811
    result = online_scan(tmp_path, delivery, world)
    table, links, summary = nvd.attach(family_world, FAMILY_ITEMS, FAMILY_FINDINGS, {}, {"maven": "osv-maven"}, None,
                                       FAMILY_LISTINGS)
    result["candidates"], result["candidate_links"], result["summary"]["candidates"] = table, links, summary
    out = tmp_path / "out"
    write_all(result, out)
    rows = {(r["id"], r["component"].split("/")[-1]): r
            for r in csv.DictReader((out / "candidates.csv").open(encoding="utf-8-sig"))}
    assert rows[("CVE-2025-1301", "web-socks@1.0")]["reached by"] == "named in the record"
    assert rows[("CVE-2025-1301", "web-all@1.0")]["reached by"] == "learned link"
    assert rows[("CVE-2025-1302", "web-core@1.0")]["same flaw as finding"] == "GHSA-f"
    assert rows[("CVE-2025-1303", "web-core@1.0")]["names only another language"] == "yes"
    assert rows[("CVE-2025-1304", "web-core@1.0")]["named classes not in this jar"] == "UrlFileNameViewController"
    assert rows[("CVE-2025-1304", "web-embed@1.0")]["named classes in this jar"] == "jar contents unknown"
    assert rows[("CVE-2025-1305", "web-core@1.0")]["learned link (package / product / project)"] == \
        "3/3 / 3/3 / 3/3; versions meet on 3 of 3"
    assert ("14 component pairs, flagged for review: same flaw as a finding 2, record names only another language 3, "
            "named classes not in the jar 1; 2 pairs left out: the record names another module; 3 CPE links refused: "
            "NVD's versions never meet OSV's") in render_summary(result)
    service = Service(Config(results=tmp_path / "results", lookup="local"),
                      net=Net(cache_dir=tmp_path / "c", offline=True, transport=ScriptedTransport({"": never})))
    scan_id = service.open_result(str(out))["scan_id"]
    listed = service.list_candidates(scan_id)["candidates"]
    # A candidate whose every pair is flagged comes last.
    assert [c["id"] for c in listed] == ["CVE-2025-1301", "CVE-2025-1302", "CVE-2025-1304", "CVE-2025-1305",
                                         "CVE-2025-1303"]
    assert listed[-1]["flags"] == ["other_language_only"] and listed[-1]["flagged_components"] == 3
    detail = service.get_candidate(scan_id, "CVE-2025-1302")
    assert [(a["component"].split("/")[-1], a["flags"]) for a in detail["affects"]] == [
        ("web-embed@1.0", []), ("web-all@1.0", []), ("web-core@1.0", ["same_flaw_as_a_finding"])]
    assert detail["affects"][-1]["same_flaw_as"] == ["GHSA-f"] and len(detail["links"]) == 3
