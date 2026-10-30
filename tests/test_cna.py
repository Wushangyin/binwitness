"""The CNAs' own records (cvelistV5): what is read of a record, which product names stand for a package, the
versions a record tells, syncing the cvelist dataset, and how its records become candidates. All records are made
up here."""
import csv
import io
import json
import zipfile

import pytest

from binwitness import cna, fixes, localdb, nvd
from binwitness.cli import main
from binwitness.cna import Range
from binwitness.localdb import LocalDb
from binwitness.mcp_server import Config, Service
from binwitness.net import Net
from binwitness.output import render_summary, write_all

from helpers import ScriptedTransport, Served, make_zip
from test_localdb import fetcher, never, osv_zip
from test_nvd import (DIFF_ROUTES, FAMILY_FINDINGS, FAMILY_ITEMS, FAMILY_LISTINGS, FAMILY_NVD, FAMILY_OSV, SPRING_ROUTE,
                      WEB, YEAR, A, B, C, D, E, cpe, feed_routes, online_scan, osv, record, spring_page)
from test_scan import delivery  # noqa: F401 (a fixture)

COMMIT = "https://github.com/acme/web/commit/" + "a" * 40


def entry(*versions, default="", vendor="Acme", product="Acme Web", package="", repository="", cpes=(), files=(),
          source="cna"):
    """An affected entry as cna.trim keeps it."""
    return {"vendor": vendor, "product": product, "package": package, "repository": repository, "cpes": list(cpes),
            "versions": list(versions), "default": default, "files": list(files), "source": source}


def v(version, status="affected", **bounds):
    return {"status": status, "version": version, **bounds}


def affected(vendor="Acme", product="Acme Web", *versions, default=None, **fields):
    """An affected entry as a CVE JSON 5 record writes it."""
    out = {"vendor": vendor, "product": product, "versions": list(versions), **fields}
    return {**out, "defaultStatus": default} if default else out


def cve5(ident, *entries, state="PUBLISHED", description=None, references=(), metrics=(), adp=(), tags=(),
         cwe="CWE-79", assigner="acme", updated="2026-10-02T00:00:00Z"):
    """A CVE JSON 5 record."""
    meta = {"cveId": ident, "state": state, "assignerShortName": assigner, "datePublished": "2026-10-01T00:00:00Z",
            "dateUpdated": updated}
    if state != "PUBLISHED":
        return {"dataType": "CVE_RECORD", "cveMetadata": meta, "containers": {"cna": {"rejectedReasons": []}}}
    container = {"title": f"A flaw in {ident}", "affected": list(entries),
                 "descriptions": [{"lang": "de", "value": "Ein Fehler."},
                                  {"lang": "en-US", "value": description or f"A flaw in {ident}."}],
                 "references": [{"url": u} for u in references], "metrics": list(metrics), "tags": list(tags),
                 "problemTypes": [{"descriptions": [{"cweId": cwe, "lang": "en", "type": "CWE"}]}],
                 "providerMetadata": {"shortName": assigner}}
    return {"dataType": "CVE_RECORD", "cveMetadata": meta, "containers": {"cna": container, "adp": list(adp)}}


def cvss(score, severity):
    return {"cvssV3_1": {"version": "3.1", "baseScore": score, "baseSeverity": severity,
                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}


# ---- records ---------------------------------------------------------------------------------------------

def test_raw_url_is_where_the_repository_keeps_a_record():
    assert cna.raw_url("CVE-2026-101296") == f"{cna.RAW}/2026/101xxx/CVE-2026-101296.json"
    assert cna.raw_url("CVE-2024-0011") == f"{cna.RAW}/2024/0xxx/CVE-2024-0011.json"


def test_trim_keeps_the_cnas_entries_and_only_the_cpes_of_an_adp():
    gadget = "cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"
    record = cve5("CVE-2026-0001", affected("Acme", "Acme Web", v("0", lessThan="2.0"), packageName=" org.acme:web ",
                                            programFiles=[f"src/main/java/A{n}.java" for n in range(30)]),
                  affected("n/a", "n/a"), "not an entry",
                  references=["https://example.org/a", COMMIT, "https://example.org/a"], tags=["disputed"],
                  adp=[{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [cvss(9.1, "critical")],
                        "affected": [affected("acme", "gadget", cpes=[gadget, 7]), affected("acme", "widget")]}])
    trimmed = cna.trim(record)
    assert [(e["product"], e["source"]) for e in trimmed["affected"]] == [("Acme Web", "cna"), ("n/a", "cna"),
                                                                          ("gadget", "adp")]
    web, _, adp = trimmed["affected"]
    assert web["package"] == "org.acme:web" and len(web["files"]) == cna.FILES_KEPT and web["default"] == ""
    assert adp["cpes"] == [gadget]
    # The CNA rated none: CISA's rating, said to be an ADP's.
    assert trimmed["cvss"] == {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                               "score": 9.1, "severity": "CRITICAL", "source": "CISA-ADP", "type": "ADP"}
    assert trimmed["description"] == "A flaw in CVE-2026-0001." and trimmed["disputed"] and trimmed["cwe"] == ["CWE-79"]
    assert trimmed["references"] == ["https://example.org/a", COMMIT] and trimmed["commits"] == [COMMIT]
    assert (trimmed["cna"], trimmed["published"], trimmed["updated"]) == ("acme", "2026-10-01T00:00:00Z",
                                                                          "2026-10-02T00:00:00Z")
    own = cna.trim(cve5("CVE-2026-0002", metrics=[cvss(5.0, "medium")],
                        adp=[{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [cvss(9.1, "critical")]}]))
    assert (own["cvss"]["score"], own["cvss"]["type"], own["cvss"]["source"]) == (5.0, "CNA", "acme")


def test_trim_keeps_only_the_state_of_a_record_not_published_and_nothing_of_one_without_an_id():
    assert cna.trim(cve5("CVE-2026-0003", state="REJECTED")) == {"id": "CVE-2026-0003", "state": "REJECTED"}
    assert cna.trim({"cveMetadata": {}}) is None and cna.trim({}) is None


# ---- what an entry names ---------------------------------------------------------------------------------

@pytest.mark.parametrize("vendor, product, key", [
    ("The Eclipse Foundation", "Eclipse Jetty", "eclipse|jetty"),
    ("eclipse", "jetty.project", "eclipse|jetty"),
    ("Apache Software Foundation", "Apache Tomcat", "apache|tomcat"),
    ("Acme", "Acme", "acme|acme"),
    ("n/a", "Acme Web", "|acme web"),
    ("Acme", "n/a", None),
    ("Acme", " Unspecified ", None),
])
def test_a_product_is_keyed_in_words_without_its_vendors_name(vendor, product, key):
    assert cna.key_of(vendor, product) == key


@pytest.mark.parametrize("package, repository, named", [
    ("org.acme.web:web-core", "", ("org.acme.web:web-core", "package")),
    ("org.acme.web:web-core", "https://repo1.maven.org/maven2/", ("org.acme.web:web-core", "package")),
    ("org.acme.web:web-core", "https://www.npmjs.com/", None),
    ("", "https://repo1.maven.org/maven2/org/acme/web/web-core/", ("org.acme.web:web-core", "repository")),
    ("", "https://github.com/acme/web", None),
    ("bcprov", "", None),
    ("@acme/web", "https://registry.npmjs.org/", None),
])
def test_the_package_an_entry_names(package, repository, named):
    assert cna.package_of(entry(package=package, repository=repository)) == named


def test_facets_are_of_the_entries_that_claim_affected_versions():
    record = {"affected": [
        entry(v("0", lessThan="2.0"), package="org.acme.web:web-core", cpes=["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"]),
        entry(v("0", lessThan="2.0"), product="Acme Web JS", repository="https://www.npmjs.com/package/acme-web",
              cpes=["cpe:/a:acme:web_js"]),
        entry(v("0", lessThan="2.0"), product="Acme Gadget", source="adp", cpes=["cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"]),
        entry(v("2.0", status="unaffected"), product="Acme Proxy", package="org.acme:proxy"),
        entry(default="affected", product="Acme Tool", cpes=["cpe:2.3:o:acme:os:*:*:*:*:*:*:*:*"]),
    ]}
    keys, packages, cpes = cna.facets(record)
    # Keys and packages come only from the CNA's own entries outside other registries; CPEs of applications only.
    assert keys == {"acme|web", "acme|tool"} and packages == {("org.acme.web:web-core", "package")}
    assert cpes == {"acme:web", "acme:web_js", "acme:gadget"}


@pytest.mark.parametrize("key, name, reads", [
    ("acme|web", "org.acme.web:web-core", True),  # "web" is any package's word, but the groupId is acme.web
    ("json smart|json smart", "net.minidev:json-smart", True),
    ("acme|crypt", "org.example:cryptolib", True),
    ("legion|bouncy castle", "org.bouncycastle:bcprov-jdk18on", True),
    ("redhat|jboss enterprise application platform", "org.jboss.resteasy:resteasy-core", False),
    ("acme|io", "org.example:iox", False),  # a short word is not a prefix of another
    ("apache|server", "org.example:server-utils", False),  # words any package could carry
    ("acme|server", "org.example:server", True),
])
def test_a_product_name_reads_as_a_package(key, name, reads):
    assert cna.stem_match(key, name) is reads


@pytest.mark.parametrize("package, name, leaves_out", [
    ("bcprov", "org.bouncycastle:bcpkix-jdk18on", True),
    ("bcprov", "org.bouncycastle:bcprov-jdk18on", False),
    ("bcprov", "org.bouncycastle:bcprov", False),
    ("web-socks", "org.acme.web:web-core", True),
    ("", "org.acme.web:web-core", False),
    ("org.acme.web:web-socks", "org.acme.web:web-core", False),  # a coordinate is another path's to read
    ("web socks", "org.acme.web:web-core", False),
])
def test_a_package_name_without_its_group_narrows_a_product(package, name, leaves_out):
    assert cna.narrows(entry(package=package), name) is leaves_out


def test_program_files_name_classes_of_main_code_only():
    found = entry(files=["web/src/main/java/org/acme/web/socks/SocksHandshakeDecoder.java",
                         "web/src/test/java/org/acme/web/SocksTest.java", "README.md", 7])
    assert cna.program_classes([found, entry()]) == ["org.acme.web.socks.SocksHandshakeDecoder"]


# ---- versions --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("versions, default, version, status", [
    ([v("1.0", lessThanOrEqual="1.2.3")], "", "1.2.3", "affected"),
    ([v("1.0", lessThanOrEqual="1.2.3")], "", "1.2.4", None),
    ([v("0", lessThan="2.0")], "", "2.0", None),
    ([v("1.0", lessThan="3.0"), v("2.0", status="unaffected", lessThan="2.5")], "", "2.1", "unaffected"),
    ([v("0", lessThan="2.0", status="unknown")], "", "1.0", None),
    # A default of affected beside a range with an upper bound: past the bound, the vendor did not look.
    ([v("0", lessThan="2.0")], "affected", "2.1", None),
    ([v("2.0", status="unaffected", lessThan="*")], "affected", "1.0", "affected"),
    ([v("2.0", status="unaffected", lessThan="*")], "affected", "2.1", "unaffected"),
    ([v("0", lessThan="2.0")], "unaffected", "2.1", "unaffected"),
    ([], "unaffected", "2.1", "unaffected"),
    ([v("1a2b3c", versionType="git", lessThan="4d5e6f")], "unaffected", "2.1", None),
    ([v("1a2b3c", versionType="git", lessThan="4d5e6f")], "", "2.1", None),
    ([v("Apache Ant 1.9.x", lessThanOrEqual="1.9.15")], "", "1.9.2", "affected"),
    ([v("Apache Ant 1.9.x", lessThanOrEqual="1.9.15")], "", "1.8.4", None),
    ([v("Apache Ant", lessThan="1.9.0")], "", "1.8.4", "affected"),
    ([v("Acme 3.x", lessThan="2.0")], "", "1.0", "affected"),  # a line past the end is no start
    ([v("v2.1.0")], "", "2.1.0", "affected"),
    ([v("v2.1.0")], "", "2.1.1", None),
    ([v("< 2.0")], "", "1.5", "affected"),
    ([v("0", lessThan="*")], "", "9.9", "affected"),
    ([v("1.0", lessThan="see the advisory")], "", "1.5", None),
])
def test_status_of_a_version(versions, default, version, status):
    assert cna.status_of(entry(*versions, default=default), version) == status


@pytest.mark.parametrize("statuses, together", [
    (["affected", None, "unaffected"], "affected"), (["unaffected", "unaffected"], "unaffected"),
    (["unaffected", None], None), ([], None)])
def test_several_entries_tell_together(statuses, together):
    assert cna.told(iter(statuses)) == together


def test_affected_versions_are_described_and_a_line_below_the_listed_ones_is_marked():
    lines = [entry(v("0", lessThan="1.2.5"), v("2.0.0", lessThan="2.0.3"), v("2.0.0", status="unaffected"))]
    assert cna.describe(lines) == "< 1.2.5; >= 2.0.0, < 2.0.3"
    assert cna.describe([entry(default="affected")]) == "all versions" and cna.describe([entry()]) == ""
    assert cna.describe_ranges([Range("1.0", "1.2", True), "1.5", Range("", None, False), "1.5"]) == \
        ">= 1.0, <= 1.2; 1.5; all versions"
    ranges = cna.affected_ranges(lines)
    # 1.0 is of a line older than any the vendor lists: one it no longer supports.
    assert [cna.below_listed_lines(ranges, x) for x in ("1.0", "1.2.4", "2.0.1", "3.0")] == [True, False, False, False]
    # One range from the first version up is the vendor saying every earlier version is affected.
    assert not cna.below_listed_lines([Range("", "1.2.5", False)], "1.0")
    assert not cna.below_listed_lines([Range("", "1.2.5", False), Range("", "1.2.9", False)], "1.0")


def test_a_vendor_advisory_lists_every_affected_line():
    advisory = {"versions": [{"introduced": "", "last_affected": "1.2.3", "fixes": ["1.2.4"]},
                             {"introduced": "v2.0.0", "last_affected": "2.0.1", "fixes": []}]}
    assert cna.advisory_ranges(advisory) == [Range("", "1.2.3", True), Range("2.0.0", "2.0.1", True)]
    assert cna.describe_ranges(cna.advisory_ranges(advisory)) == "<= 1.2.3; >= 2.0.0, <= 2.0.1"
    assert [cna.advisory_status(advisory, x) for x in ("1.2.3", "1.3", "2.0.0", "2.0.2")] == \
        ["affected", "unaffected", "affected", "unaffected"]
    assert cna.advisory_status({"versions": []}, "1.0") is None and cna.advisory_status(None, "1.0") is None


# ---- learning which product names a package --------------------------------------------------------------

def osv_ranges(cve, name, *events):
    record = osv(f"GHSA-{cve}", cve, name)
    record["affected"][0]["ranges"][0]["events"] = list(events)
    return record


@pytest.mark.parametrize("osv_events, cna_versions, meet", [
    ([{"introduced": "0"}, {"fixed": "0.5"}], [v("0", lessThan="0.5")], True),
    # The same fix, spelled two ways, and with no bound in common.
    ([{"introduced": "0"}, {"fixed": "4.1.125.Final"}], [v("0", lessThan="4.1.125")], True),
    ([{"introduced": "0"}, {"fixed": "2.0"}], [v("1.0", lessThan="1.5")], True),
    ([{"introduced": "0"}, {"fixed": "0.5"}], [v("3.0", lessThan="3.5")], False),
    ([{"introduced": "0"}, {"fixed": "0.5"}], [], None),
])
def test_osvs_and_a_cnas_versions_meet(osv_events, cna_versions, meet):
    records = [osv_ranges("CVE-2026-0001", "org.acme:web", *osv_events)]
    entries = [entry(*cna_versions, default="affected")]
    assert cna._meet(records, "org.acme:web", "CVE-2026-0001", entries) is meet
    assert cna._meet([], "org.acme:web", "CVE-2026-0001", entries) is None


def test_a_product_name_is_learned_from_the_cves_osv_attributes():
    def found(*names, versions=(v("0", lessThan="0.5"),)):
        return [(name, entry(*versions)) for name in names]
    attributed = {"CVE-2026-0001": {"org.acme.web:web-core"}, "CVE-2026-0002": {"org.acme.web:web-core"},
                  "CVE-2026-0003": {"org.acme.web:web-core"},
                  # Learned from one CVE, a link must read as the package: zeta|engine does, acme|tool does not.
                  "CVE-2026-0011": {"org.zeta:engine"}, "CVE-2026-0021": {"org.beta:tool-kit"},
                  # The CNA's versions are of another numbering.
                  "CVE-2026-0031": {"org.gamma:gamma"}, "CVE-2026-0032": {"org.gamma:gamma"},
                  # A record of two products tells neither.
                  "CVE-2026-0041": {"org.delta:delta"}, "CVE-2026-0042": {"org.delta:delta"}}
    keys = {**{f"CVE-2026-000{n}": found("acme|web") for n in (1, 2, 3)},
            "CVE-2026-0011": found("zeta|engine"), "CVE-2026-0021": found("acme|tool"),
            **{f"CVE-2026-003{n}": found("gamma|gamma", versions=[v("3.0", lessThan="3.5")]) for n in (1, 2)},
            **{f"CVE-2026-004{n}": found("delta|delta", "delta|appliance") for n in (1, 2)}}
    records = {name: [osv_ranges(c, name, {"introduced": "0"}, {"fixed": "0.5"}) for c, n in attributed.items()
                      if name in n] for name in set().union(*attributed.values())}
    asked = []

    def osv_records(name):
        asked.append(name)
        return records[name]
    assert cna.learn(attributed, keys, osv_records) == {"acme|web": {"org.acme.web:web-core": 3},
                                                        "zeta|engine": {"org.zeta:engine": 1}}
    assert "org.delta:delta" not in asked and "org.beta:tool-kit" not in asked


# ---- the cvelist dataset and its candidates --------------------------------------------------------------

def web(ident, *versions, description=None, updated="2026-10-02T00:00:00Z", **fields):
    return cve5(ident, affected("Acme", "Acme Web", *versions, **fields), description=description, updated=updated)


UP_TO_2 = v("0", lessThan="2.0")
# The family of test_nvd (org.acme.web), whose CVEs OSV attributes are Acme / Acme Web in their CNA's records too,
# and records NVD has given no CPE yet, each reaching the family's jars, or not, its own way.
SNAPSHOT = [
    *[web(f"CVE-2024-100{n}", v("0", lessThan="0.5")) for n in (1, 2, 3)],
    web("CVE-2026-2001", UP_TO_2, description="Acme Web before 2.0 mishandles cookies."),  # NVD received it
    web("CVE-2026-2002", UP_TO_2, packageName="org.acme.web:web-socks", collectionURL="https://repo1.maven.org/maven2"),
    web("CVE-2026-2003", v("0", lessThan="1.2.5")),
    web("CVE-2026-2004", v("1a2b3c", versionType="git", lessThan="4d5e6f")),
    web("CVE-2026-2005", UP_TO_2, packageName="web-socks"),
    web("CVE-2026-2006", UP_TO_2, description="SocksHandshakeDecoder in org.acme.web:web-socks before 2.0 reads past "
                                              "the buffer."),
    web("CVE-2026-2007", UP_TO_2),  # NVD analysed it: another product
    cve5("CVE-2026-2008", affected("n/a", "n/a", UP_TO_2, cpes=["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"])),
    cve5("CVE-2026-2009", affected("Acme", "Acme Spring Thing", v("0", lessThan="9.0"))),
    web("CVE-2026-2010", UP_TO_2),
]
TWO_LINES = web("CVE-2026-2003", v("0", lessThan="1.2.5"), v("2.0.0", lessThan="2.0.3"),
                updated="2026-10-29T12:00:00Z")
FETCHED = cve5("CVE-2026-2009", affected("Acme", "Acme Spring Thing", v("0", lessThan="9.0")),
               description="Acme Spring Thing lets a header through.")


def releases(*tags):
    return "".join(f'<link rel="alternate" href="{cna.CVELIST}/releases/tag/{t}"/>' for t in tags).encode()


class _Unseekable(io.RawIOBase):
    def __init__(self):
        self.data = bytearray()

    def writable(self):
        return True

    def write(self, chunk):
        self.data += chunk
        return len(chunk)


def snapshot(*records, streamed=True):
    """A midnight snapshot: a zip holding cves.zip. Written as a stream, its entries' sizes follow their data."""
    inner = {f"cves/2026/2xxx/{r['cveMetadata']['cveId']}.json": json.dumps(r) for r in records}
    if streamed:
        return Served(make_zip({"cves.zip": make_zip(inner)}))
    out = _Unseekable()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in inner.items():
            archive.writestr(name, text)
    return Served(make_zip({"cves.zip": bytes(out.data)}))


def delta(*records):
    return Served(make_zip({f"deltaCves/{r['cveMetadata']['cveId']}.json": json.dumps(r) for r in records}))


def advisory_page(*more):
    page = spring_page(("CVE-2026-2009", "October 20, 2026", []), *more)
    page["result"]["data"]["cves"]["nodes"][0]["fields"]["affected"] = json.dumps({
        "artifacts": ["org.acme.web:web-core"],
        "versions": [{"last-affected": "1.2.3"}, {"introduced": "2.0.0", "last-affected": "2.0.1"}]})
    return page


@pytest.fixture
def cna_world(tmp_path, monkeypatch):
    monkeypatch.setattr(nvd, "FIRST_YEAR", YEAR)
    db = LocalDb(tmp_path / "db")
    transport = ScriptedTransport({
        "/Maven/all.zip": osv_zip(*FAMILY_OSV),
        **feed_routes(f"nvdcve-2.0-{YEAR}", *FAMILY_NVD, record("CVE-2026-2001", status="Received"),
                      record("CVE-2026-2007", cpe("other", "gadget"))),
        SPRING_ROUTE: advisory_page(),
        "/releases.atom": releases("cve_2026-10-29_2200Z", "cve_2026-10-29_2300Z", "cve_2026-10-28_2300Z"),
        "/2026-10-29_all_CVEs_at_midnight.zip.zip": snapshot(*SNAPSHOT),
        "/2026-10-29_delta_CVEs_at_2300Z.zip": delta(cve5("CVE-2026-2010", state="REJECTED")),
        "/2026-10-29_delta_CVEs_at_end_of_day.zip": delta(TWO_LINES),
        "/2026-10-30_delta_CVEs_at_0100Z.zip": delta(),
        "/CVE-2026-2009.json": json.dumps(FETCHED).encode(),
    })
    logged = []

    def sync(*names):
        return db.sync(list(names), fetcher=fetcher(transport), log=logged.append)
    assert sync("cvelist")["cvelist"].startswith("failed: what is kept of the CNAs' records follows the CVEs OSV")
    sync("osv-maven", "nvd")
    # Before the vendor's advisory names it, CVE-2026-2009 is a record of no package: kept without its text.
    assert sync("cvelist") == {"cvelist": "downloaded 12 records, 11 kept with their text; 1 product names learned"}
    assert db.state["cvelist"]["data_as_of"] == "2026-10-29T23:00:00Z"
    assert db.cna_records(["CVE-2026-2009", "CVE-2026-2010"]) == {}
    assert db.cna_links("org.acme.web:web-core") == {"acme|web": 3}
    sync("spring")
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0100Z", "cve_2026-10-29_2300Z")
    assert sync("cvelist") == {"cvelist": "updated: 1 record changed; 1 product names learned"}
    assert db.cna_records(["CVE-2026-2009"])["CVE-2026-2009"]["description"] == \
        "Acme Spring Thing lets a header through."
    assert sync("cvelist") == {"cvelist": "up to date"}
    return db, transport, sync, logged


def test_cvelist_installs_follows_the_days_changes_and_fetches_the_texts_it_comes_to_need(cna_world):
    db, transport, sync, logged = cna_world
    asked = [url for _, url, _ in transport.calls]
    # The snapshot is first asked for one byte, to learn whether it can be fetched in parts.
    assert [u.rsplit("/", 1)[1] for u in dict.fromkeys(asked) if "/releases/download/" in u] == [
        "2026-10-29_all_CVEs_at_midnight.zip.zip", "2026-10-29_delta_CVEs_at_2300Z.zip",
        "2026-10-29_delta_CVEs_at_end_of_day.zip", "2026-10-30_delta_CVEs_at_0100Z.zip"]
    assert f"{cna.CVELIST}/releases/download/cve_2026-10-29_at_end_of_day/2026-10-29_delta_CVEs_at_end_of_day.zip" \
        in asked
    assert [u for u in asked if "raw.githubusercontent" in u] == [cna.raw_url("CVE-2026-2009")]
    row = next(r for r in db.status() if r["name"] == "cvelist")
    assert (row["records"], row["kept"], row["links"], row["bodies_not_fetched"], row["tag"]) == \
        (12, 12, 1, 0, "cve_2026-10-30_0100Z")
    # A day whose changes are no longer published: the list is downloaded again, and a snapshot whose entries'
    # sizes follow their data is unpacked first.
    transport.routes["/releases.atom"] = releases("cve_2026-10-31_0000Z")
    transport.routes["/2026-10-31_all_CVEs_at_midnight.zip.zip"] = snapshot(*SNAPSHOT[:4], streamed=False)
    transport.routes["/2026-10-31_delta_CVEs_at_0000Z.zip"] = delta()
    assert sync("cvelist") == {"cvelist": "downloaded 4 records, 4 kept with their text; 1 product names learned"}
    assert any("no longer published" in line for line in logged)
    assert db.cna_meta(["CVE-2026-2002"]) == {}


def test_cvelist_fetches_so_many_texts_a_sync_and_says_how_many_are_left(cna_world, monkeypatch):
    db, transport, sync, _ = cna_world
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0200Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0200Z.zip"] = delta(cve5(
        "CVE-2026-2011", affected("Acme", "Acme Spring Thing", UP_TO_2)))
    assert sync("cvelist") == {"cvelist": "updated: 1 record changed; 1 product names learned"}
    transport.routes[SPRING_ROUTE] = advisory_page(("CVE-2026-2011", "October 21, 2026", ["org.acme.web:web-core"]))
    sync("spring")
    monkeypatch.setattr(localdb, "CVELIST_FETCH_LIMIT", 0)
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0300Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0300Z.zip"] = delta()
    assert sync("cvelist") == {"cvelist": "updated: 0 records changed; 1 product names learned; 1 records still to "
                                          "fetch: sync cvelist again later"}
    assert next(r for r in db.status() if r["name"] == "cvelist")["bodies_not_fetched"] == 1


def test_cna_records_reach_the_jars_nvd_cannot_tell_of_yet(cna_world):
    db, *_ = cna_world
    table, _, summary = nvd.attach(db, FAMILY_ITEMS, FAMILY_FINDINGS, {}, {"maven": "osv-maven"}, None,
                                   FAMILY_LISTINGS)
    core, everything, embed, socks = (i["purl"] for i in FAMILY_ITEMS)

    def pairs(ident):
        return {ref: a["basis"] for ref, a in table[ident]["affects"].items()}
    learned = {core: "cna_learned", everything: "cna_learned", embed: "cna_learned"}
    assert pairs("CVE-2026-2001") == learned
    # A record that names its package reaches its builds and, by its product name, nothing else.
    assert pairs("CVE-2026-2002") == {socks: "cna_package"}
    assert pairs("CVE-2026-2003") == learned
    # Named for web-socks: of the others, only the all-in-one jar that holds the named class.
    assert pairs("CVE-2026-2006") == {everything: "cna_learned"}
    assert pairs("CVE-2026-2008") == {core: "cna_cpe", everything: "cna_cpe", embed: "cna_cpe"}
    assert pairs("CVE-2026-2009") == {core: "advisory_direct"}
    # Versions told by revisions only; a package name of another module; NVD's own CPE; rejected.
    assert not {"CVE-2026-2004", "CVE-2026-2005", "CVE-2026-2007", "CVE-2026-2010"} & set(table)

    received, socks_record, two_lines = table["CVE-2026-2001"], table["CVE-2026-2002"], table["CVE-2026-2003"]
    assert (received["status"], received["url"], received["record_from"]) == (
        "Received", f"{nvd.NVD_CVE}/CVE-2026-2001", "cna")
    assert (socks_record["status"], socks_record["url"]) == (nvd.NOT_IN_NVD, f"{nvd.CVE_ORG}CVE-2026-2002")
    assert received["description"] == "Acme Web before 2.0 mishandles cookies."
    assert (received["cna"], received["cna_published"], received["cna_updated"]) == (
        "acme", "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")
    pair = received["affects"][core]
    assert {k: pair[k] for k in ("cpe", "versions", "basis", "single_cve_link", "versions_from", "below_listed_lines",
                                 "cna_product")} == {
        "cpe": "", "versions": "< 2.0", "basis": "cna_learned", "single_cve_link": False, "versions_from": "cna",
        "below_listed_lines": False, "cna_product": "Acme / Acme Web"}
    assert two_lines["affects"][core]["versions"] == "< 1.2.5; >= 2.0.0, < 2.0.3"
    assert all(a["below_listed_lines"] for a in two_lines["affects"].values())
    assert table["CVE-2026-2008"]["affects"][embed]["single_cve_link"]
    assert table["CVE-2026-2008"]["affects"][core]["cpe"] == "acme:web"
    advised = table["CVE-2026-2009"]["affects"][core]
    assert (advised["versions"], advised["versions_from"], advised["below_listed_lines"], advised["cna_product"]) == (
        "<= 1.2.3; >= 2.0.0, <= 2.0.1", "advisory", True, "Acme Web")
    assert table["CVE-2026-2009"]["description"] == "Acme Spring Thing lets a header through."
    assert table["CVE-2026-2006"]["affects"][everything]["classes_in_jar"] == ["SocksHandshakeDecoder"]
    # The CVEs NVD has analysed are as before (test_nvd), and from NVD.
    assert all(table[i]["record_from"] == "nvd" for i in table if i.startswith("CVE-2025-"))

    assert summary["pairs"] == 26
    assert summary["pairs_by_basis"] == {"advisory_direct": 1, "cna_cpe": 3, "cna_learned": 7, "cna_package": 1,
                                         "learned": 13, "named": 1}
    assert summary["pairs_versions_from"] == {"advisory": 1, "cna": 11, "nvd": 14}
    assert summary["records_from_cna"] == 6 and summary["pairs_flagged"]["below_listed_lines"] == 4
    assert summary["pairs_left_out"] == {"names_another_module": 4, "package_name_narrows": 3,
                                         "versions_not_told": 3}
    assert summary["data_as_of"]["cvelist"] == "2026-10-30T01:00:00Z"


def test_a_package_read_from_a_repository_url_is_known_by_a_jar_that_is_its_published_artifact(cna_world):
    db, transport, sync, _ = cna_world
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0200Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0200Z.zip"] = delta(web(
        "CVE-2026-2011", UP_TO_2, collectionURL="https://repo1.maven.org/maven2/org/acme/web/web-socks/"))
    sync("cvelist")
    core, everything, embed, socks = (i["purl"] for i in FAMILY_ITEMS)

    def reached(confidence):
        items = [{**i, "confidence": confidence} for i in FAMILY_ITEMS]
        table, _, _ = nvd.attach(db, items, FAMILY_FINDINGS, {}, {"maven": "osv-maven"}, None, FAMILY_LISTINGS)
        return {ref: a["basis"] for ref, a in table["CVE-2026-2011"]["affects"].items()}
    # Neither OSV nor a hash index knows web-socks, and CNAs miswrite such paths: the record stands for no package,
    # and reaches the family by its product name.
    assert reached("declared") == {core: "cna_learned", everything: "cna_learned", embed: "cna_learned"}
    # A jar here that is the published artifact of web-socks shows the package exists.
    assert reached("exact") == reached("content") == {socks: "cna_package"}


def test_cna_records_reach_the_files_the_mcp_tools_and_the_db_status(tmp_path, delivery, cna_world,  # noqa: F811
                                                                      capsys):
    db, *_ = cna_world
    result = online_scan(tmp_path, delivery, db)
    table, links, summary = nvd.attach(db, FAMILY_ITEMS, FAMILY_FINDINGS, {}, {"maven": "osv-maven"}, None,
                                       FAMILY_LISTINGS)
    result["candidates"], result["candidate_links"], result["summary"]["candidates"] = table, links, summary
    out = tmp_path / "out"
    write_all(result, out)
    rows = {(r["id"], r["component"].split("/")[-1]): r
            for r in csv.DictReader((out / "candidates.csv").open(encoding="utf-8-sig"))}
    columns = ("nvd status", "reached by", "affected versions", "versions from", "only on a line below those listed",
               "product in the CNA's record", "cna", "cna published", "url")

    def row(ident, component):
        return tuple(rows[(ident, component)][c] for c in columns)
    assert row("CVE-2026-2001", "web-core@1.0") == (
        "Received", "learned link (product in the CNA's record)", "< 2.0", "CNA's record", "", "Acme / Acme Web",
        "acme", "2026-10-01", f"{nvd.NVD_CVE}/CVE-2026-2001")
    assert row("CVE-2026-2002", "web-socks@1.0")[:2] == (nvd.NOT_IN_NVD, "package named in the CNA's record")
    assert row("CVE-2026-2002", "web-socks@1.0")[-1] == f"{nvd.CVE_ORG}CVE-2026-2002"
    assert row("CVE-2026-2003", "web-core@1.0")[2:5] == ("< 1.2.5; >= 2.0.0, < 2.0.3", "CNA's record", "yes")
    assert row("CVE-2026-2008", "web-embed@1.0")[1] == "CPE in the CNA's record"
    assert row("CVE-2026-2009", "web-core@1.0")[1:6] == (
        "module named in the vendor's advisory, with its versions", "<= 1.2.3; >= 2.0.0, <= 2.0.1",
        "vendor's advisory", "yes", "Acme Web")
    assert rows[("CVE-2025-1301", "web-socks@1.0")]["versions from"] == "NVD"
    assert "cvelist 2026-10-30" in rows[("CVE-2026-2001", "web-core@1.0")]["data as of"]
    text = render_summary(result)
    assert "only on a line below those the vendor lists 4" in text
    assert ("pairs left out: the record names another module 4, the CNA's package name leaves the build out 3, "
            "the CNA's record does not tell whether the version is affected 3") in text

    service = Service(Config(results=tmp_path / "results", lookup="local"),
                      net=Net(cache_dir=tmp_path / "c", offline=True, transport=ScriptedTransport({"": never})))
    scan_id = service.open_result(str(out))["scan_id"]
    detail = service.get_candidate(scan_id, "CVE-2026-2009")
    assert (detail["candidate"]["record_from"], detail["candidate"]["status"]) == ("cna", nvd.NOT_IN_NVD)
    assert [(a["component"].split("/")[-1], a["basis"], a["versions_from"], a["flags"]) for a in detail["affects"]] == [
        ("web-core@1.0", "advisory_direct", "advisory", ["below_listed_lines"])]
    # A CNA's product name finds its candidates, as a CPE does NVD's.
    found = service.list_candidates(scan_id, text="acme web")["candidates"]
    assert {c["id"] for c in found} == {"CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003", "CVE-2026-2006",
                                        "CVE-2026-2009"}
    assert {c["cna"] for c in found} == {"acme"}

    capsys.readouterr()
    assert main(["db", "status", "--db-dir", str(db.directory)]) == 0
    lines = capsys.readouterr().out.splitlines()
    at = next(i for i, text in enumerate(lines) if text.lstrip().startswith("cvelist"))
    assert "12 records  data as of 2026-10-30 01:00 UTC" in lines[at]
    assert lines[at + 1].strip() == "12 kept with their text, 1 product names learned"


def security_page(*entries):
    """A vendor's security page: each entry opens with its title in bold, then names its CVE and the fix commits."""
    return "".join(f'<p><strong>{title}</strong> <a href="https://www.cve.org/CVERecord?id={ident}">{ident}</a></p>'
                   + "".join(f'<p>Fixed with <a href="{WEB}/commit/{sha}">{sha[:7]}</a>.</p>' for sha in shas)
                   for title, ident, shas in entries).encode()


def test_a_vendors_security_page_gives_the_commits_of_its_fixes():
    page = security_page(("Important: cookies", "CVE-2026-2001", [B, C]), ("Low: headers", "CVE-2026-2006", []),
                         ("Important: cookies, the 1.x line", "CVE-2026-2001", [C]))
    assert fixes.page_commits(page.decode()) == {"CVE-2026-2001": [f"acme/web@{B}", f"acme/web@{C}"]}
    assert fixes.page_commits('<p><strong>Low</strong> <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?'
                              f'name=CVE-2026-2006">x</a> <a href="{WEB}/commit/{A}">a</a></p>') == {
        "CVE-2026-2006": [f"acme/web@{A}"]}


@pytest.mark.parametrize("path, found", [
    ("web/src/main/java/org/acme/web/core/Server.java", ("java", "org.acme.web.core.Server")),
    ("src/main/jdk1.4/org/acme/web/core/Server.java", ("jdk1.4", "org.acme.web.core.Server")),
    ("java/org/acme/web/core/Server.java", ("java", "org.acme.web.core.Server")),  # an Ant build's main code
    ("web/java/org/acme/web/core/Server.java", None),
    ("test/org/acme/web/core/ServerTest.java", None),
    ("web/src/test/java/org/acme/web/core/ServerTest.java", None),
])
def test_main_code_is_where_a_build_keeps_it(path, found):
    assert fixes.main_source(path) == found


def test_fixes_are_read_for_the_cnas_records_and_from_a_vendors_page(cna_world, monkeypatch):
    db, transport, sync, logged = cna_world
    monkeypatch.setattr(localdb, "RECORD_PAGE", 2)
    # An attributed CVE's record refers to acme/web: the project's repository, for its product name.
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0400Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0400Z.zip"] = delta(
        cve5("CVE-2024-1001", affected("Acme", "Acme Web", v("0", lessThan="0.5")),
             references=[f"{WEB}/releases/tag/v0.5"], updated="2026-10-30T03:10:00Z"),
        cve5("CVE-2026-2003", affected("Acme", "Acme Web", v("0", lessThan="1.2.5")),
             references=[f"{WEB}/commit/{A}", f"https://github.com/other/bundle/commit/{'f' * 40}"],
             updated="2026-10-30T03:20:00Z"),
        # NVD gave it a CPE of another product: what it is about is not read from the product its CNA names.
        cve5("CVE-2026-2007", affected("Acme", "Acme Web", UP_TO_2), references=[f"{WEB}/commit/{E}"],
             updated="2026-10-30T03:30:00Z"))
    assert sync("cvelist")["cvelist"].startswith("updated: 3 records changed")
    transport.routes.update(DIFF_ROUTES)
    transport.routes["/security-9.html"] = security_page(("Important: cookies", "CVE-2026-2001", [B, C]))
    outcome = sync("fixes")["fixes"]
    assert outcome.startswith("fetched 3 commits")
    assert any("security-8.html could not be fetched (404)" in line for line in logged)
    # The CNA's record of a CVE NVD has given no CPE: its commit of the project, the other kept apart.
    from_cna = db.fix_of("CVE-2026-2003")
    assert from_cna["classes"] == ["org.acme.web.socks.SocksHandshakeDecoder"]
    assert from_cna["elsewhere"] == [f"https://github.com/other/bundle/commit/{'f' * 40}"]
    assert db.fix_of("CVE-2026-2007") is None
    # The vendor's page names the fix of a record that cites none: its commits are the patch.
    from_page = db.fix_of("CVE-2026-2001")
    assert (from_page["classes"], from_page["classes_from"]) == (
        ["org.acme.web.core.Server", "org.acme.web.servlet.UrlFilenameViewController"], "patch-tagged commits")
    # A record published since cites a commit fixes has not read: the sync that brought it says so.
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0500Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0500Z.zip"] = delta(cve5(
        "CVE-2026-2013", affected("Acme", "Acme Web", v("0", lessThan="1.2.5")), references=[f"{WEB}/commit/{D}"],
        updated="2026-10-30T04:30:00Z"))
    assert sync("cvelist")["fixes"] == "not synced: 1 commit the records now cite not read yet (sync fixes)"
    assert sync("fixes")["fixes"].startswith("fetched 1 commit")
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0600Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0600Z.zip"] = delta(cve5("CVE-2026-2014", updated="2026-10-30T05:30:00Z"))
    assert "fixes" not in sync("cvelist")


def test_cvelist_counts_the_records_that_changed_not_those_a_release_repeats(cna_world):
    _, transport, sync, _ = cna_world
    new = web("CVE-2026-2012", UP_TO_2, updated="2026-10-30T01:30:00Z")
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0200Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0200Z.zip"] = delta(new)
    assert sync("cvelist")["cvelist"].startswith("updated: 1 record changed;")
    # An hour's release holds every change of its day so far: those stored already are not counted again; a
    # record withdrawn is.
    changed = web("CVE-2026-2003", v("0", lessThan="1.2.6"), updated="2026-10-30T02:30:00Z")
    withdrawn = cve5("CVE-2026-2002", state="REJECTED", updated="2026-10-30T02:40:00Z")
    transport.routes["/releases.atom"] = releases("cve_2026-10-30_0300Z")
    transport.routes["/2026-10-30_delta_CVEs_at_0300Z.zip"] = delta(new, changed, withdrawn)
    assert sync("cvelist")["cvelist"].startswith("updated: 2 records changed;")
    # The day's end repeats its hours; the next day's first hour brings one more.
    transport.routes["/releases.atom"] = releases("cve_2026-10-31_0000Z")
    transport.routes["/2026-10-30_delta_CVEs_at_end_of_day.zip"] = delta(new, changed, withdrawn)
    transport.routes["/2026-10-31_delta_CVEs_at_0000Z.zip"] = delta(
        web("CVE-2026-2004", UP_TO_2, updated="2026-10-31T00:10:00Z"))
    assert sync("cvelist")["cvelist"].startswith("updated: 1 record changed;")

