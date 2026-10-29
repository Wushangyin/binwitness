"""End-to-end scans against a scripted network."""
import base64
import hashlib
import json

import pytest

from binwitness.crosscheck import crosscheck, load_other
from binwitness.net import Net, NetError, OfflineMiss
from binwitness.output import cyclonedx, render_summary, write_all
from binwitness.scan import Options, scan

from binwitness import maven

from helpers import ScriptedTransport, Served, make_jar, make_zip

PUBLISHED = make_jar("org.example", "lib", "1.0")
REBUILT = make_jar("org.example", "patched", "2.0", {"extra.txt": "local change"})
MODULES = "\n".join(f"{m}.version=4.1.54.Final" for m in ("netty-common", "netty-codec-http"))
NETTY_ALL = make_jar("io.netty", "netty-all", "4.1.54.Final", {"META-INF/io.netty.versions.properties": MODULES})
OWN = make_jar("com.acme", "service", "1.0-SNAPSHOT")


def sha1_b64(data):
    return base64.b64encode(hashlib.sha1(data).digest()).decode()


def advisory(osv_id, cve, package, severity="HIGH", fixed="9.9"):
    return {"id": osv_id, "aliases": [cve], "modified": "2024-01-01T00:00:00Z", "published": "2023-01-01T00:00:00Z",
            "summary": f"flaw in {package}", "database_specific": {"severity": severity},
            "affected": [{"package": {"ecosystem": "Maven", "name": package},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


RECORDS = {
    "GHSA-aaaa": advisory("GHSA-aaaa", "CVE-2023-0001", "org.example:lib", "CRITICAL", "1.1"),
    "GHSA-bbbb": advisory("GHSA-bbbb", "CVE-2023-0002", "io.netty:netty-codec-http", "MODERATE", "4.1.77.Final"),
    "CVE-2023-0002": {**advisory("CVE-2023-0002", "GHSA-bbbb", "io.netty:netty-codec-http", "LOW"),
                      "aliases": ["GHSA-bbbb"]},
}
AFFECTED = {"org.example:lib": ["GHSA-aaaa"], "io.netty:netty-codec-http": ["GHSA-bbbb", "CVE-2023-0002"]}


def querybatch(method, url, body):
    queries = json.loads(body)["queries"]
    return {"results": [{"vulns": [{"id": i, "modified": RECORDS[i]["modified"]}
                                   for i in AFFECTED.get(q["package"]["name"], [])]} for q in queries]}


def package_query(method, url, body):
    """Every record of a package, the question upgrade advice asks."""
    name = json.loads(body)["package"]["name"]
    return {"vulns": [RECORDS[i] for i in AFFECTED.get(name, [])]}


def metadata(*versions):
    listed = "".join(f"<version>{v}</version>" for v in versions)
    return f"<metadata><versioning><versions>{listed}</versions></versioning></metadata>".encode()


def routes(**overrides):
    table = {
        "/systems/maven/packages/org.example%3Apatched/": {"licenses": ["non-standard"]},
        f"hash.value={sha1_b64(PUBLISHED).replace('+', '%2B').replace('/', '%2F').replace('=', '%3D')}": {
            "results": [{"version": {"versionKey": {"system": "MAVEN", "name": "org.example:lib", "version": "1.0"},
                                     "licenses": ["Apache-2.0"]}}]},
        f"hash.value={sha1_b64(NETTY_ALL).replace('+', '%2B').replace('/', '%2F').replace('=', '%3D')}": {
            "results": [{"version": {"versionKey": {"system": "MAVEN", "name": "io.netty:netty-all",
                                                    "version": "4.1.54.Final"}, "licenses": ["Apache-2.0"]}}]},
        "hash.value=": {"results": []},
        "solrsearch": {"response": {"docs": []}},
        "/org/example/patched/2.0/patched-2.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567  patched-2.0.jar",
        "/org/example/patched/2.0/patched-2.0.pom":
            b"<project><licenses><license><name>GNU General Public License v3</name></license></licenses></project>",
        "/systems/maven/packages/": {"licenses": ["Apache-2.0"]},
        "querybatch": querybatch,
        "/v1/vulns/": lambda m, url, b: RECORDS[url.rsplit("/", 1)[1]],
        "known_exploited": {"vulnerabilities": [{"cveID": "CVE-2023-0001", "dateAdded": "2024-02-02"}]},
        # After "querybatch", which contains this.
        "/v1/query": package_query,
        "/org/example/lib/maven-metadata.xml": metadata("1.0", "1.1", "2.0-RC1"),
        "/io/netty/netty-codec-http/maven-metadata.xml": metadata("4.1.54.Final", "4.1.77.Final"),
    }
    table.update(overrides)
    return table


@pytest.fixture
def delivery(tmp_path):
    bundle = make_zip({"lib/lib-1.0.jar": PUBLISHED, "lib/patched-2.0.jar": REBUILT,
                       "lib/netty-all-4.1.54.Final.jar": NETTY_ALL, "lib/service-1.0-SNAPSHOT.jar": OWN,
                       "lib/mystery.jar": make_zip({"a.class": b"\xca\xfe", "META-INF/LICENSE": "MIT License\n"})})
    path = tmp_path / "delivery.zip"
    path.write_bytes(bundle)
    return path


def run(tmp_path, delivery, transport, **options):
    net = Net(cache_dir=tmp_path / "cache", transport=transport, sleep=lambda s: None)
    return scan([delivery], net, Options(first_party_groups=("com.acme",), scan_js=False, **options),
                log=lambda m: None), net


def refuse(method, url, body):
    raise AssertionError(f"unexpected request {url}")


def test_maven_mirror_answers_for_central(tmp_path, delivery):
    direct, _ = run(tmp_path / "direct", delivery, ScriptedTransport(routes()))
    transport = ScriptedTransport({"repo1.maven.org": refuse, **routes()})
    net = Net(cache_dir=tmp_path / "cache", transport=transport, sleep=lambda s: None,
              mirrors={maven.CENTRAL: "https://mirror.example/central"})
    mirrored = scan([delivery], net, Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None)
    assert mirrored["components"] == direct["components"]
    assert any(url.startswith("https://mirror.example/central/org/example/patched/") for _, url, _ in transport.calls)
    assert "mirror.example" in mirrored["data_sources"]["online"]
    assert mirrored["options"]["mirrors"] == {maven.CENTRAL: "https://mirror.example/central"}
    offline = Net(cache_dir=tmp_path / "cache", offline=True, transport=lambda *a: refuse(*a[:3]))
    with pytest.raises(OfflineMiss):
        offline.get(f"{maven.CENTRAL}/org/example/patched/2.0/patched-2.0.pom")


def test_scan_identifies_with_evidence(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    by_name = {c["name"]: c for c in result["components"]}
    lib = by_name["org.example:lib"]
    assert lib["confidence"] == "exact" and lib["files"][0]["published"] == "identical"
    assert lib["license"] == {"expressions": ["Apache-2.0"], "source": "deps.dev", "family": "permissive"}
    patched = by_name["org.example:patched"]
    assert patched["confidence"] == "declared" and patched["files"][0]["published"] == "differs"
    assert patched["license"] == {"names": ["GPL-3.0"], "source": "Maven Central POM", "family": "strong-copyleft"}
    module = by_name["io.netty:netty-codec-http"]
    assert module["contained_in"] == ["pkg:maven/io.netty/netty-all@4.1.54.Final"] and module["files"] == []
    assert [u["filename"] for u in result["unidentified"]] == ["mystery.jar"]
    assert result["unidentified"][0]["license"] == {"names": ["MIT"], "source": "jar: META-INF/LICENSE",
                                                    "family": "permissive"}
    assert [f["filename"] for f in result["first_party"]] == ["service-1.0-SNAPSHOT.jar"]


def test_scan_vulnerabilities_are_deduplicated_by_cve(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    table = result["vulnerabilities"]
    assert sorted(table) == ["CVE-2023-0001", "CVE-2023-0002"]
    assert table["CVE-2023-0002"]["severity"] == "MEDIUM"          # the higher of the two records
    assert sorted(table["CVE-2023-0002"]["osv_ids"]) == ["CVE-2023-0002", "GHSA-bbbb"]
    assert table["CVE-2023-0001"]["kev_date_added"] == "2024-02-02"
    assert table["CVE-2023-0001"]["affects"] == {"pkg:maven/org.example/lib@1.0": {"fixed": ["1.1"]}}
    summary = result["summary"]
    assert summary["vulnerabilities"]["by_severity"]["CRITICAL"] == 1
    assert summary["jars"]["differ_from_published"] == 1


def test_offline_replays_the_cache_and_reports_misses(tmp_path, delivery):
    run(tmp_path, delivery, ScriptedTransport(routes()))
    silent = ScriptedTransport()
    net = Net(cache_dir=tmp_path / "cache", offline=True, transport=silent)
    result = scan([delivery], net, Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None)
    assert silent.calls == []
    assert sorted(result["vulnerabilities"]) == ["CVE-2023-0001", "CVE-2023-0002"]
    with pytest.raises(OfflineMiss):
        net.get("https://example.invalid/never-fetched")


def test_retries_then_gives_up(tmp_path):
    attempts = []

    def flaky(method, url, body, headers):
        attempts.append(url)
        if len(attempts) < 3:
            raise OSError("network unreachable")
        return 200, b"{}", {}

    net = Net(cache_dir=tmp_path, transport=flaky, sleep=lambda s: None)
    assert net.get_json("https://example.invalid/x") == {}
    assert len(attempts) == 3
    down = Net(cache_dir=tmp_path, transport=lambda *a: (503, b"", {}), sleep=lambda s: None, retries=2)
    with pytest.raises(NetError):
        down.get("https://example.invalid/y")


def test_outputs(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    paths = write_all(result, tmp_path / "out")
    assert all(p.exists() for p in paths)
    bom = cyclonedx(result)
    assert bom["specVersion"] == "1.5"
    refs = {c["bom-ref"] for c in bom["components"]}
    assert all(a["ref"] in refs for v in bom["vulnerabilities"] for a in v["affects"])


def test_crosscheck_classifies_the_other_tools_extra_findings(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    other = tmp_path / "other.csv"
    other.write_text("component,version,vulnerability\n"
                     "org.example:lib,1.0,CVE-2023-0001\n"
                     "org.example:lib,1.0,CVE-2023-9001\n"        # advisory for a sibling module
                     "org.example:lib,1.0,CVE-2023-9002\n"        # unreviewed, no package
                     "io.netty:netty-all,4.1.54.Final,CVE-2023-9003\n"   # names a bundled module
                     "org.example:lib,1.0,VENDOR-2023-77\n"
                     "io.netty:netty-codec-http,4.1.54.Final,CVE-2023-0002|VENDOR-2023-78\n"   # paired ids
                     "io.netty:netty-codec-http,4.1.54.Final,\n", encoding="utf-8")

    def advisories(method, url, body):
        if "CVE-2023-9001" in url and "type=reviewed" in url:
            return [{"ghsa_id": "GHSA-x1", "vulnerabilities": [
                {"package": {"ecosystem": "maven", "name": "org.example:lib-extras"},
                 "vulnerable_version_range": "< 2.0"}]}]
        if "CVE-2023-9002" in url and "type=unreviewed" in url:
            return [{"ghsa_id": "GHSA-x2", "vulnerabilities": []}]
        if "CVE-2023-9003" in url and "type=reviewed" in url:
            return [{"ghsa_id": "GHSA-x3", "vulnerabilities": [
                {"package": {"ecosystem": "maven", "name": "io.netty:netty-codec-http"},
                 "vulnerable_version_range": "< 4.1.60.Final"}]}]
        return []

    net = Net(cache_dir=tmp_path / "cache", transport=ScriptedTransport({"api.github.com": advisories}),
              sleep=lambda s: None)
    report = crosscheck(result, load_other(str(other)), net)
    classes = {x["id"]: x["class"] for x in report["only_theirs"]}
    assert classes == {"CVE-2023-9001": "same-project-other-module", "CVE-2023-9002": "unattributed",
                       "CVE-2023-9003": "bundled-module", "VENDOR-2023-77": "tool-specific-id"}
    assert report["summary"]["findings_in_both"] == 2
    assert load_other(str(other))[("maven", "io.netty:netty-codec-http", "4.1.54.Final")] == {"CVE-2023-0002"}
    assert [x["id"] for x in report["only_ours"]] == []


def test_a_rerun_refetches_only_records_that_really_changed(tmp_path, delivery):
    def batch_at(stamp):
        def answer(method, url, body):
            queries = json.loads(body)["queries"]
            return {"results": [{"vulns": [{"id": i, "modified": stamp} for i in AFFECTED.get(q["package"]["name"], [])]}
                                for q in queries]}
        return answer

    # The record carries nanoseconds, querybatch the same instant in microseconds.
    precise = {i: {**r, "modified": "2024-01-01T00:00:00.123456789Z"} for i, r in RECORDS.items()}
    table = routes(querybatch=batch_at("2024-01-01T00:00:00.123456Z"),
                   **{"/v1/vulns/": lambda m, url, b: precise[url.rsplit("/", 1)[1]]})
    run(tmp_path, delivery, ScriptedTransport(table))
    again = ScriptedTransport(table)
    run(tmp_path, delivery, again)
    assert again.calls == []

    newer = ScriptedTransport({**table, "querybatch": batch_at("2024-03-01T00:00:00Z")})
    net = Net(cache_dir=tmp_path / "cache", transport=newer, sleep=lambda s: None, max_age_hours=0)
    scan([delivery], net, Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None)
    assert sum("/v1/vulns/" in c[1] for c in newer.calls) == len(RECORDS)


def test_a_jar_shipped_inside_an_unmodified_release_is_not_reported_as_modified(tmp_path):
    inner = make_jar("org.example", "inner", "1.0", {"Inner.class": b"\xca\xfe"})
    outer = make_jar("org.example", "outer", "1.0", {"inner-1.0.jar": inner})
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"lib/outer-1.0.jar": outer}))
    outer_hash = sha1_b64(outer).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    table = {f"hash.value={outer_hash}": {"results": [{"version": {
                 "versionKey": {"system": "MAVEN", "name": "org.example:outer", "version": "1.0"},
                 "licenses": ["Apache-2.0"]}}]},
             # upstream's build of inner differs from the inner-1.0.jar it published separately
             "/org/example/inner/1.0/inner-1.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567  inner-1.0.jar",
             **routes()}
    result, _ = run(tmp_path, path, ScriptedTransport(table))
    files = {f["filename"]: f for c in result["components"] for f in c["files"]}
    assert (files["outer-1.0.jar"]["published"], files["outer-1.0.jar"]["confidence"]) == ("identical", "exact")
    assert (files["inner-1.0.jar"]["published"], files["inner-1.0.jar"]["confidence"]) == ("inside-published",
                                                                                           "declared")
    assert result["summary"]["jars"]["differ_from_published"] == 0


def test_a_declared_jar_matching_the_published_checksum_is_exact(tmp_path):
    jar = make_jar("org.example", "unindexed", "1.0")
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"lib/unindexed-1.0.jar": jar}))
    sha1 = hashlib.sha1(jar).hexdigest()
    table = {"/org/example/unindexed/1.0/unindexed-1.0.jar.sha1": f"{sha1}  unindexed-1.0.jar".encode(), **routes()}
    result, _ = run(tmp_path, path, ScriptedTransport(table))
    (component,) = result["components"]
    assert component["confidence"] == "exact"
    assert (component["files"][0]["confidence"], component["files"][0]["published"]) == ("exact", "identical")


POM = "groupId=org.example\nartifactId=rezipped\nversion=3.0\n"
CONTENTS = {"org/example/Lib.class": b"\xca\xfe\xba\xbe" + bytes(range(256)) * 4, "org/example/messages.txt": "hello"}
RELEASE = make_zip({"META-INF/": b"", "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nBundle-Version: 3.0\r\n\r\n",
                    "META-INF/maven/org.example/rezipped/pom.properties": POM, "org/": b"", "org/example/": b"",
                    **CONTENTS})


def rezipped_scan(tmp_path, local, release=RELEASE):
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"BOOT-INF/lib/rezipped-3.0.jar": local}))
    table = {"/org/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
             "/org/example/rezipped/3.0/rezipped-3.0.jar": release, **routes()}
    result, _ = run(tmp_path, path, ScriptedTransport(table))
    (file,) = [f for c in result["components"] for f in c["files"]]
    return result, file


@pytest.mark.parametrize("tail, ranges", [(maven.TAIL, True), (64, True), (maven.TAIL, False)],
                         ids=["directory-in-tail", "second-request", "server-ignores-range"])
def test_a_rezipped_jar_with_unchanged_entries_is_repackaged_not_modified(tmp_path, monkeypatch, tail, ranges):
    monkeypatch.setattr(maven, "TAIL", tail)
    # What a fat-jar build does to its dependencies: directories dropped, manifest rewritten, entries re-dated.
    local = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nCreated-By: repacker\r\n\r\n",
                      "META-INF/maven/org.example/rezipped/pom.properties": POM, **CONTENTS})
    result, file = rezipped_scan(tmp_path, local, Served(RELEASE, ranges))
    assert (file["published"], file["confidence"]) == ("repackaged", "content")
    assert file["comparison"]["packaging_only"] == ["META-INF/MANIFEST.MF"]
    assert file["comparison"]["counts"] == {"changed": 0, "added": 0, "removed": 0}
    assert (result["summary"]["jars"]["differ_from_published"], result["summary"]["jars"]["repackaged"]) == (0, 1)


def test_a_rezipped_jar_with_a_changed_class_still_differs_and_names_it(tmp_path):
    local = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                      "META-INF/maven/org.example/rezipped/pom.properties": POM,
                      **CONTENTS, "org/example/Lib.class": b"\xca\xfe\xba\xbe patched", "org/example/Extra.class": b"x"})
    result, file = rezipped_scan(tmp_path, local, Served(RELEASE))
    assert file["published"] == "differs"
    assert (file["comparison"]["changed"], file["comparison"]["added"]) == (["org/example/Lib.class"],
                                                                            ["org/example/Extra.class"])
    assert result["summary"]["jars"]["differ_from_published"] == 1


def test_a_class_edited_under_its_old_crc_is_not_taken_for_a_repackaging(tmp_path):
    local = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                      "META-INF/maven/org.example/rezipped/pom.properties": POM, **CONTENTS})
    original = CONTENTS["org/example/Lib.class"]
    # Entries are stored uncompressed, so the class bytes can be swapped in place, headers and CRC untouched.
    tampered = local.replace(original, original[:4] + b"\x00" * (len(original) - 4))
    assert tampered != local
    result, file = rezipped_scan(tmp_path, tampered, Served(RELEASE))
    assert file["published"] == "differs" and "comparison" not in file
    assert any("Lib.class" in w and "CRC" in w for w in result["warnings"])


# A Gradle build: no pom.properties. Delivered re-zipped under a scrambled name, so neither hash nor name helps.
GRADLE_RELEASE = make_zip({"META-INF/": b"", "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n", **CONTENTS})
SCRAMBLED = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nCreated-By: repacker\r\n\r\n", **CONTENTS})
# A jar that shades org.example.Lib among its own classes; search lists it first.
UBER = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n", **CONTENTS, "org/example/uber/Main.class": b"u"})


def class_search_table(search_calls):
    def search(method, url, body):
        search_calls.append(url)
        return {"response": {"docs": [{"g": "org.example", "a": "uber", "v": "3.0"},
                                      {"g": "org.example", "a": "rezipped", "v": "3.0"}]}}
    return {"fc%3Aorg.example.Lib": search,
            "/org/example/uber/3.0/uber-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
            "/org/example/uber/3.0/uber-3.0.jar": Served(UBER),
            "/org/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
            "/org/example/rezipped/3.0/rezipped-3.0.jar": Served(GRADLE_RELEASE), **routes()}


def test_class_search_identifies_a_rebuilt_jar_by_its_contents_and_skips_wrong_candidates(tmp_path):
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"BOOT-INF/lib/qbcz-3.0.jar": SCRAMBLED}))
    calls = []
    result, _ = run(tmp_path, path, ScriptedTransport(class_search_table(calls)), class_search=True)
    (component,) = result["components"]
    assert (component["name"], component["version"], component["confidence"]) == ("org.example:rezipped", "3.0",
                                                                                   "content")
    assert component["files"][0]["published"] == "repackaged" and "org.example.Lib" in component["evidence"][0]["method"]
    assert len(calls) == 1 and "v%3A%28%223.0%22%29" in calls[0]
    assert result["unidentified"] == []


# The release with its pom.properties taken out, and the same classes republished under another groupId with
# a manifest of its own. Neither groupId is the package, so search order decides, and it lists the copy first.
STRIPPED = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nBundle-Version: 3.0\r\n\r\n", **CONTENTS})
MIRROR = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nBundle-SymbolicName: mirror\r\n\r\n",
                   "META-INF/maven/org.example.mirror/rezipped/pom.properties": POM.replace("org.example",
                                                                                            "org.example.mirror"),
                   **CONTENTS})


def test_class_search_names_the_closest_of_several_published_copies_and_keeps_the_others(tmp_path):
    record = advisory("GHSA-dddd", "CVE-2023-0004", "example:rezipped", "CRITICAL", "3.1")

    def search(method, url, body):
        return {"response": {"docs": [{"g": "org.example.mirror", "a": "rezipped", "v": "3.0"},
                                      {"g": "example", "a": "rezipped", "v": "3.0"}]}}

    def batch(method, url, body):
        return {"results": [{"vulns": [{"id": "GHSA-dddd", "modified": record["modified"]}]
                             if q["package"]["name"] == "example:rezipped" else []}
                            for q in json.loads(body)["queries"]]}
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"BOOT-INF/lib/qbcz-3.0.jar": STRIPPED}))
    table = {"fc%3Aorg.example.Lib": search,
             "/org/example/mirror/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
             "/org/example/mirror/rezipped/3.0/rezipped-3.0.jar": Served(MIRROR),
             "/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
             "/example/rezipped/3.0/rezipped-3.0.jar": Served(RELEASE),
             **routes(querybatch=batch, **{"/v1/vulns/": lambda m, url, b: {**RECORDS, "GHSA-dddd": record}[
                 url.rsplit("/", 1)[1]]})}
    result, _ = run(tmp_path, path, ScriptedTransport(table), class_search=True)
    (component,) = result["components"]
    assert (component["name"], component["confidence"]) == ("example:rezipped", "content")
    assert component["files"][0]["comparison"]["packaging_only"] == [
        "META-INF/maven/org.example/rezipped/pom.properties"]
    assert component["files"][0]["also_published_as"] == ["pkg:maven/org.example.mirror/rezipped@3.0"]
    assert component["vulnerabilities"] == ["CVE-2023-0004"]


def test_without_class_search_no_class_name_leaves_the_machine(tmp_path):
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"BOOT-INF/lib/qbcz-3.0.jar": SCRAMBLED}))
    calls = []
    result, _ = run(tmp_path, path, ScriptedTransport(class_search_table(calls)))
    assert calls == [] and [u["filename"] for u in result["unidentified"]] == ["qbcz-3.0.jar"]


def test_the_only_pom_properties_of_a_shading_jar_names_a_contained_library_not_the_jar(tmp_path):
    host = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                     "META-INF/maven/org.example/rezipped/pom.properties": POM,
                     **{f"com/host/C{i}.class": bytes([i]) for i in range(10)},
                     "com/host/internal/example/Lib.class": CONTENTS["org/example/Lib.class"]})
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"BOOT-INF/lib/kxvw-4.1.0.jar": host}))
    table = {"/org/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
             "/org/example/rezipped/3.0/rezipped-3.0.jar": Served(RELEASE), **routes()}
    result, _ = run(tmp_path, path, ScriptedTransport(table))
    (unidentified,) = result["unidentified"]
    assert unidentified["filename"] == "kxvw-4.1.0.jar"
    assert unidentified["embedded_coordinates"] == ["org.example:rezipped:3.0"]
    (component,) = result["components"]
    assert component["contained_in"] == ["kxvw-4.1.0.jar"] and component["files"] == []


def test_a_jar_whose_packages_were_renamed_keeps_its_declared_coordinate_and_names_the_rename(tmp_path):
    fork = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                     "META-INF/maven/org.example/rezipped/pom.properties": POM,
                     **{name.replace("org/example/", "cn/fork/"): data for name, data in CONTENTS.items()}})
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"BOOT-INF/lib/fork-driver-5.0.0.jar": fork}))
    table = {"/org/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
             "/org/example/rezipped/3.0/rezipped-3.0.jar": Served(RELEASE), **routes()}
    result, _ = run(tmp_path, path, ScriptedTransport(table))
    (component,) = result["components"]
    assert (component["name"], component["confidence"]) == ("org.example:rezipped", "declared")
    assert component["files"][0]["published"] == "differs"
    assert component["files"][0]["comparison"]["relocated"] == {"from": "org/example", "to": "cn/fork", "entries": 2}
    assert result["unidentified"] == []


# One file, published under two groupIds; it carries no pom.properties to say which.
TWIN = make_zip({"net/sf/json/JSONObject.class": b"\xca\xfe\xba\xbe"})
TWIN_RECORD = advisory("GHSA-cccc", "CVE-2023-0003", "net.sf.json-lib:json-lib", "HIGH", "2.5")


def twin_routes(*names):
    def batch(method, url, body):
        return {"results": [{"vulns": [{"id": "GHSA-cccc", "modified": TWIN_RECORD["modified"]}]
                             if q["package"]["name"] == "net.sf.json-lib:json-lib" else []}
                            for q in json.loads(body)["queries"]]}
    hits = [{"version": {"versionKey": {"system": "MAVEN", "name": n, "version": "2.4"}, "licenses": []}}
            for n in names]
    encoded = sha1_b64(TWIN).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    return {f"hash.value={encoded}": {"results": hits},
            **routes(querybatch=batch, **{"/v1/vulns/": lambda m, url, b: {**RECORDS, "GHSA-cccc": TWIN_RECORD}[
                url.rsplit("/", 1)[1]]})}


@pytest.fixture
def twin(tmp_path):
    path = tmp_path / "twin.zip"
    path.write_bytes(make_zip({"lib/json-lib-2.4.jar": TWIN}))
    return path


def test_advisory_filed_under_the_other_coordinate_of_the_same_file_counts(tmp_path, twin):
    result, _ = run(tmp_path, twin, ScriptedTransport(twin_routes("org.example.mirror:json-lib", "net.sf.json-lib:json-lib")))
    [component] = result["components"]
    assert component["purl"] == "pkg:maven/org.example.mirror/json-lib@2.4"
    assert component["files"][0]["also_published_as"] == ["pkg:maven/net.sf.json-lib/json-lib@2.4"]
    assert component["vulnerabilities"] == ["CVE-2023-0003"]
    assert result["vulnerabilities"]["CVE-2023-0003"]["affects"] == {
        "pkg:maven/org.example.mirror/json-lib@2.4": {"fixed": ["2.5"], "via": "pkg:maven/net.sf.json-lib/json-lib@2.4"}}
    # Whichever of the two a lookup names first, the file gets the same advisories.
    swapped, _ = run(tmp_path / "swapped", twin,
                     ScriptedTransport(twin_routes("net.sf.json-lib:json-lib", "org.example.mirror:json-lib")))
    assert swapped["components"][0]["vulnerabilities"] == ["CVE-2023-0003"]
    assert "via" not in swapped["vulnerabilities"]["CVE-2023-0003"]["affects"]["pkg:maven/net.sf.json-lib/json-lib@2.4"]
    out = tmp_path / "out"
    write_all(result, out)
    assert "advisory names pkg:maven/net.sf.json-lib/json-lib@2.4" in (out / "vulnerabilities.csv").read_text()
    assert {"name": "binwitness:also-published-as", "value": "pkg:maven/net.sf.json-lib/json-lib@2.4"} in \
        cyclonedx(result)["components"][0]["properties"]


def test_crosscheck_matches_a_component_named_by_its_other_coordinate(tmp_path, twin):
    result, net = run(tmp_path, twin, ScriptedTransport(twin_routes("org.example.mirror:json-lib", "net.sf.json-lib:json-lib")))
    other = tmp_path / "other.csv"
    other.write_text("component,version,vulnerability\nnet.sf.json-lib:json-lib,2.4,CVE-2023-0003\n"
                     "net.sf.json-lib:json-lib,2.4,CVE-2023-9004\n")   # GitHub has it, OSV does not

    def advisories(method, url, body):
        if "CVE-2023-9004" in url and "type=reviewed" in url:
            return [{"ghsa_id": "GHSA-x4", "vulnerabilities": [
                {"package": {"ecosystem": "maven", "name": "net.sf.json-lib:json-lib"},
                 "vulnerable_version_range": "< 2.5"}]}]
        return []

    github = Net(cache_dir=tmp_path / "github", transport=ScriptedTransport({"api.github.com": advisories}),
                 sleep=lambda s: None)
    report = crosscheck(result, load_other(str(other)), github)
    assert report["summary"]["findings_in_both"] == 1
    assert report["identification"]["theirs_not_ours"] == []
    assert [(x["id"], x["class"]) for x in report["only_theirs"]] == [("CVE-2023-9004", "confirmed")]


# A Gradle build (no pom.properties) and the copy a vendor renamed and re-zipped.
CODEC_CONTENTS = {"org/example/codec/Codec.class": b"\xca\xfe\xba\xbe codec", "org/example/codec/table.bin": b"\x00\x01"}
CODEC = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n", **CODEC_CONTENTS})
CODEC_COPY = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nCreated-By: repacker\r\n\r\n", **CODEC_CONTENTS})


def hash_route(data, name, version):
    encoded = sha1_b64(data).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    return {f"hash.value={encoded}": {"results": [{"version": {
        "versionKey": {"system": "MAVEN", "name": name, "version": version}, "licenses": ["Apache-2.0"]}}]}}


def copies_scan(tmp_path, files, table, **options):
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip(files))
    transport = ScriptedTransport({**table, **routes()})
    result, _ = run(tmp_path, path, transport, **options)
    return result, transport


def test_a_renamed_rezipped_copy_takes_the_coordinate_of_the_identified_jar_with_the_same_entries(tmp_path):
    result, transport = copies_scan(tmp_path, {"lib/codec-1.5.jar": CODEC, "lib/frghf-1.5.jar": CODEC_COPY},
                                    hash_route(CODEC, "org.example:codec", "1.5"), class_search=True)
    (component,) = result["components"]
    assert (component["name"], component["version"]) == ("org.example:codec", "1.5")
    files = {f["filename"]: f for f in component["files"]}
    copy = files["frghf-1.5.jar"]
    assert (copy["confidence"], copy["published"]) == ("content", "repackaged")
    assert copy["same_entries_as"] == hashlib.sha1(CODEC).hexdigest() and "same_entries_as" not in files["codec-1.5.jar"]
    assert any("codec-1.5.jar in the same delivery" in e["method"] for e in component["evidence"])
    assert result["unidentified"] == [] and result["summary"]["jars"]["copies_of_identified_jars"] == 1
    # The copy needed no class search: nothing about it left the machine but its hash.
    assert not any("fc%3A" in url for _, url, _ in transport.calls)


def test_a_copy_matching_releases_of_different_versions_stays_unidentified_and_names_them(tmp_path):
    older = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nImplementation-Version: 1.4\r\n\r\n",
                      **CODEC_CONTENTS})
    result, _ = copies_scan(tmp_path, {"lib/codec-1.5.jar": CODEC, "lib/codec-1.4.jar": older,
                                       "lib/frghf.jar": CODEC_COPY},
                            {**hash_route(CODEC, "org.example:codec", "1.5"),
                             **hash_route(older, "org.example:codec", "1.4")})
    (unidentified,) = result["unidentified"]
    assert unidentified["filename"] == "frghf.jar"
    assert unidentified["same_content_as"] == ["org.example:codec:1.4", "org.example:codec:1.5"]
    assert "same_content_as" in unidentified["reason"]


def test_jars_holding_only_a_license_and_a_notice_are_not_matched_as_copies(tmp_path):
    notices = {"META-INF/LICENSE.txt": "Apache License 2.0", "META-INF/NOTICE.txt": "Example project"}
    starter = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n", **notices})
    renamed = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nCreated-By: repacker\r\n\r\n", **notices})
    result, _ = copies_scan(tmp_path, {"lib/starter-web-2.0.jar": starter, "lib/vwduwhu-mail-2.0.jar": renamed},
                            hash_route(starter, "org.example:starter-web", "2.0"))
    assert [u["filename"] for u in result["unidentified"]] == ["vwduwhu-mail-2.0.jar"]
    assert "holds no code" in result["unidentified"][0]["reason"]


def test_a_jar_bundling_a_whole_library_among_more_of_its_own_is_not_that_library(tmp_path):
    host = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                     "META-INF/maven/org.example/rezipped/pom.properties": POM, **CONTENTS,
                     **{f"com/host/C{i}.class": bytes([i]) for i in range(10)}})
    result, _ = copies_scan(tmp_path, {"BOOT-INF/lib/label-tags-1.0.1.jar": host},
                            {"/org/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
                             "/org/example/rezipped/3.0/rezipped-3.0.jar": Served(RELEASE)})
    (unidentified,) = result["unidentified"]
    assert unidentified["filename"] == "label-tags-1.0.1.jar"
    assert unidentified["embedded_coordinates"] == ["org.example:rezipped:3.0"]
    (component,) = result["components"]
    assert component["contained_in"] == ["label-tags-1.0.1.jar"] and component["files"] == []


SHADED_POM = "groupId=org.example\nartifactId=annotations\nversion=1.1\n"
# The release itself carries the pom.properties of a library it shades, so a renamed copy has two and
# neither matches the file name.
SHADING_ENTRIES = {"META-INF/maven/org.example/rezipped/pom.properties": POM,
                   "META-INF/maven/org.example/annotations/pom.properties": SHADED_POM,
                   **CONTENTS, "org/example/shaded/schema/Type.class": b"\xca\xfe\xba\xbe schema"}
SHADING_RELEASE = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nBundle-SymbolicName: org.example.rezipped\r\n\r\n",
                            **SHADING_ENTRIES})


def test_a_renamed_jar_with_several_pom_properties_is_the_one_whose_release_has_its_entries(tmp_path):
    renamed = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nBundle-SymbolicName: org.example.rezipped\r\n"
                                                "Created-By: repacker\r\n\r\n", **SHADING_ENTRIES})
    result, transport = copies_scan(
        tmp_path, {"BOOT-INF/lib/uhclssha-3.0.jar": renamed},
        {"/org/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
         "/org/example/rezipped/3.0/rezipped-3.0.jar": Served(SHADING_RELEASE)})
    by_name = {c["name"]: c for c in result["components"]}
    jar = by_name["org.example:rezipped"]
    assert (jar["confidence"], jar["files"][0]["published"], jar["contained_in"]) == ("content", "repackaged", [])
    assert "one of the jar's pom.properties" in jar["evidence"][0]["method"]
    assert by_name["org.example:annotations"]["contained_in"] == ["pkg:maven/org.example/rezipped@3.0"]
    assert result["unidentified"] == []
    # The manifest named the right candidate first, so the shaded library's release was never fetched.
    assert not any("/org/example/annotations/" in url for _, url, _ in transport.calls)


def test_rewritten_maven_build_metadata_counts_as_packaging(tmp_path):
    # A build that re-zips its dependencies regenerates pom.properties (a new timestamp) and may add a pom.xml.
    local = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                      "META-INF/maven/org.example/rezipped/pom.properties": "#Generated by Maven\n#Tue Oct 29\n" + POM,
                      "META-INF/maven/org.example/rezipped/pom.xml": "<project/>", **CONTENTS})
    result, file = rezipped_scan(tmp_path, local, Served(RELEASE))
    assert file["published"] == "repackaged"
    assert file["comparison"]["counts"] == {"changed": 0, "added": 0, "removed": 0}
    assert "META-INF/maven/org.example/rezipped/pom.properties" in file["comparison"]["packaging_only"]


MILESTONES = "https://repo.example/milestone"


def published_on_milestones(path, data):
    return {f"{MILESTONES}/{path}.sha1": hashlib.sha1(data).hexdigest().encode()}


def test_a_release_published_only_on_another_repository(tmp_path):
    jar = make_jar("org.example", "preview", "2.0-RC1")
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"lib/preview-2.0-RC1.jar": jar}))
    table = {**published_on_milestones("org/example/preview/2.0-RC1/preview-2.0-RC1.jar", jar),
             f"{MILESTONES}/org/example/preview/2.0-RC1/preview-2.0-RC1.pom":
                 b"<project><licenses><license><name>Eclipse Public License - v 2.0</name></license></licenses></project>",
             "/systems/maven/packages/org.example%3Apreview/": {"licenses": []}, **routes()}
    central_only, _ = run(tmp_path / "a", path, ScriptedTransport(table))
    assert central_only["summary"]["jars"]["not_on_central"] == 1
    result, _ = run(tmp_path / "b", path, ScriptedTransport(table), maven_repos=(MILESTONES,))
    (component,) = result["components"]
    assert (component["confidence"], component["files"][0]["published"]) == ("exact", "identical")
    assert component["files"][0]["repository"] == MILESTONES and MILESTONES in component["evidence"][0]["method"]
    assert component["license"] == {"names": ["EPL-2.0"], "source": f"POM from {MILESTONES}", "family": "weak-copyleft"}
    assert result["summary"]["jars"]["not_on_central"] == 0


# Two jars of one project built with Gradle (no pom.properties), released on a milestone repository only. The
# logging bridge's classes live in another project's package, so only its sibling names its groupId.
CORE = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                 "org/widget/core/Engine.class": b"\xca\xfe\xba\xbe engine"})
BRIDGE = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                   "org/legacy/logging/LogFactory.class": b"\xca\xfe\xba\xbe bridge"})


def test_class_search_guesses_coordinates_from_the_file_name_and_from_identified_siblings(tmp_path):
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"lib/widget-core-2.0-RC1.jar": CORE, "lib/widget-logging-2.0-RC1.jar": BRIDGE}))
    table = {**published_on_milestones("org/widget/widget-core/2.0-RC1/widget-core-2.0-RC1.jar", CORE),
             **published_on_milestones("org/widget/widget-logging/2.0-RC1/widget-logging-2.0-RC1.jar", BRIDGE),
             **routes()}
    result, _ = run(tmp_path, path, ScriptedTransport(table), class_search=True, maven_repos=(MILESTONES,))
    found = {c["name"]: c for c in result["components"]}
    assert sorted(found) == ["org.widget:widget-core", "org.widget:widget-logging"]
    assert all(c["confidence"] == "exact" and c["files"][0]["repository"] == MILESTONES for c in found.values())
    assert "file name or manifest" in found["org.widget:widget-logging"]["evidence"][0]["method"]
    assert result["unidentified"] == []


def test_unidentified_jars_say_why_and_what_their_manifest_claims(tmp_path):
    titled = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nImplementation-Title: Widget Toolkit\r\n"
                                               "Implementation-Version: 3.1\r\n\r\n", "w/W.class": b"\xca\xfe"})
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"lib/broken.jar": b"not a zip at all", "lib/titled.jar": titled}))
    result, _ = run(tmp_path, path, ScriptedTransport(routes()))
    reasons = {u["filename"]: (u["reason"], u["hint"]) for u in result["unidentified"]}
    assert reasons["broken.jar"] == ("not a readable zip archive (truncated, damaged or not a jar at all)", None)
    assert reasons["titled.jar"] == ("no registry has this file and the jar declares no Maven coordinates",
                                     "Widget Toolkit 3.1")


def test_a_failed_vulnerability_lookup_is_reported_not_taken_for_none(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes(querybatch=(503, b""))))
    assert result["vulnerabilities"] == {}
    assert result["summary"]["incomplete"]["vulnerabilities_not_checked"] == len(result["components"])
    assert all(c["vulnerabilities_checked"] is False for c in result["components"])
    assert "INCOMPLETE" in render_summary(result)
    bom = cyclonedx(result)
    assert all({"name": "binwitness:vulnerabilities", "value": "not checked: the lookup failed"} in c["properties"]
               for c in bom["components"] if c["type"] == "library")


def test_an_empty_input_says_so(tmp_path):
    (tmp_path / "empty").mkdir()
    result = scan([tmp_path / "empty"], Net(cache_dir=tmp_path / "cache", transport=refuse), Options(),
                  log=lambda m: None)
    assert any(w.startswith("nothing to identify") for w in result["warnings"])
    summary = render_summary(result)
    assert summary.splitlines()[:2] == ["components   0", "jars         0 distinct"]


def test_sbom_lists_every_file_with_hashes_and_license_ids(tmp_path):
    relabeled = make_jar("org.example", "lib", "1.0", {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n"
                                                                                "Created-By: other\r\n\r\n"})
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip({"lib/lib-1.0.jar": PUBLISHED, "other/lib-1.0.jar": relabeled,
                               "lib/patched-2.0.jar": REBUILT, "lib/service-1.0-SNAPSHOT.jar": OWN,
                               "lib/mystery.jar": make_zip({"a.class": b"\xca\xfe", "META-INF/LICENSE": "MIT License\n"})}))
    result, _ = run(tmp_path, path, ScriptedTransport(routes()))
    bom = cyclonedx(result)
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))
    lib = [c for c in bom["components"] if c.get("purl") == "pkg:maven/org.example/lib@1.0"]
    assert sorted(c["bom-ref"] for c in lib) == sorted(f"pkg:maven/org.example/lib@1.0#{hashlib.sha1(d).hexdigest()}"
                                                       for d in (PUBLISHED, relabeled))
    (critical,) = [v for v in bom["vulnerabilities"] if v["id"] == "CVE-2023-0001"]
    assert sorted(a["ref"] for a in critical["affects"]) == sorted(c["bom-ref"] for c in lib)
    by_name = {c["name"]: c for c in bom["components"]}
    assert by_name["patched"]["licenses"] == [{"license": {"id": "GPL-3.0"}}]
    assert by_name["mystery.jar"]["type"] == "file" and by_name["mystery.jar"]["licenses"] == [{"license": {"id": "MIT"}}]
    assert [h["alg"] for h in by_name["service-1.0-SNAPSHOT.jar"]["hashes"]] == ["SHA-1", "SHA-256"]
    assert bom["metadata"]["component"]["name"] == "delivery.zip"
    assert bom["metadata"]["component"]["hashes"][0]["content"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_csv_files_open_in_spreadsheets_as_utf8(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    paths = write_all(result, tmp_path / "out")
    assert all(p.read_bytes().startswith(b"\xef\xbb\xbf") for p in paths if p.suffix == ".csv")


def test_crosscheck_finds_a_cve_that_osv_relates_to_an_advisory_of_the_project(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    other = tmp_path / "other.csv"
    other.write_text("component,version,vulnerability\norg.example:lib,1.0,CVE-2023-7001\n"
                     "org.example:lib,1.0,CVE-2023-7002\n", encoding="utf-8")
    related = {
        "GHSA-rel1": {**advisory("GHSA-rel1", "GHSA-rel1", "org.example:lib", fixed="1.1"), "aliases": [],
                      "related": ["CVE-2023-7001"]},
        "GHSA-rel2": {**advisory("GHSA-rel2", "GHSA-rel2", "org.example:lib-extras", fixed="2.0"), "aliases": [],
                      "related": ["CVE-2023-7002"]},
    }
    modules = {"org.example:lib": ["GHSA-rel1"], "org.example:lib-extras": ["GHSA-rel2"]}

    def batch(method, url, body):
        queries = json.loads(body)["queries"]
        assert all("version" not in q for q in queries)
        return {"results": [{"vulns": [{"id": i} for i in modules.get(q["package"]["name"], [])]} for q in queries]}

    transport = ScriptedTransport({
        "api.github.com": [],
        "g%3A%22org.example%22": {"response": {"docs": [{"g": "org.example", "a": "lib"},
                                                         {"g": "org.example", "a": "lib-extras"}]}},
        "querybatch": batch, "/v1/vulns/": lambda m, url, b: related[url.rsplit("/", 1)[1]]})
    report = crosscheck(result, load_other(str(other)), Net(cache_dir=tmp_path / "cc", transport=transport,
                                                            sleep=lambda s: None))
    verdicts = {x["id"]: (x["class"], x["detail"]) for x in report["only_theirs"]}
    assert verdicts["CVE-2023-7001"][0] == "confirmed" and "GHSA-rel1" in verdicts["CVE-2023-7001"][1]
    assert verdicts["CVE-2023-7002"][0] == "same-project-other-module"
    assert "org.example:lib-extras" in verdicts["CVE-2023-7002"][1]
    assert sum("g%3A%22org.example%22" in url for _, url, _ in transport.calls) == 1


def test_upgrade_advice_names_the_nearest_release_outside_the_advisories(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    named = {c["name"]: c for c in result["components"]}
    lib = named["org.example:lib"]["upgrade"]
    # 2.0-RC1 is newer but a release candidate.
    assert (lib["verdict"], lib["target"], lib["clears"]) == ("upgrade", "1.1", ["CVE-2023-0001"])
    assert lib["versions_source"] == {"source": "maven-metadata.xml", "repositories": [maven.CENTRAL]}
    codec = named["io.netty:netty-codec-http"]["upgrade"]
    # Two records of CVE-2023-0002 disagree (4.1.77.Final, 9.9): the one that covers more decides.
    assert (codec["verdict"], codec["target"]) == ("no-published-fix", None)
    assert codec["fix_versions_not_published"] == [{"id": "CVE-2023-0002", "fixed": "9.9"}]
    assert [c["code"] for c in codec["caveats"]] == ["embedded-in-host"]
    assert result["summary"]["upgrades"] == {"by_verdict": {"upgrade": 1, "no-published-fix": 1},
                                             "fix_versions_not_published": 1, "families": 0}
    assert "upgrade_versions_not_checked" not in result["summary"]["incomplete"]
    summary = render_summary(result)
    assert "CVE-2023-0001        org.example:lib 1.0, upgrade to 1.1 KEV" in summary
    assert "upgrades     upgrade on the same line 1, no published fix 1; 1 advisory names a fixed version that " \
           "is not published" in summary
    out = tmp_path / "out"
    write_all(result, out)
    rows = {r.split(",")[1]: r for r in (out / "components.csv").read_text("utf-8-sig").splitlines()}
    assert rows["name"].endswith(",upgrade,upgrade family") and rows["org.example:lib"].endswith(",upgrade 1.1,")
    assert {"name": "binwitness:upgrade", "value": "upgrade 1.1"} in next(
        c for c in cyclonedx(result)["components"] if c["name"] == "lib")["properties"]
    # A member of a release family: the family's advice leads, so the column alone does not split the family.
    named["org.example:lib"]["upgrade_family"] = "org.example@1.0"
    result["upgrade_families"] = [{"family": "org.example@1.0", "group": "org.example", "version": "1.0",
                                   "members": [named["org.example:lib"]["purl"], "pkg:maven/org.example/b@1.0"],
                                   "verdict": "upgrade", "target": "1.2", "remaining": ["CVE-2023-0009"]}]
    write_all(result, out)
    rows = {r.split(",")[1]: r for r in (out / "components.csv").read_text("utf-8-sig").splitlines()}
    assert rows["org.example:lib"].endswith(",upgrade 1.2 (1 remain) with its family (alone: upgrade 1.1),"
                                            "org.example@1.0 (2 artifacts): upgrade 1.2 (1 remain)")


def test_without_upgrade_advice_no_version_list_or_package_query_is_fetched(tmp_path, delivery):
    transport = ScriptedTransport(routes())
    result, _ = run(tmp_path, delivery, transport, upgrades=False)
    assert not any("maven-metadata.xml" in url or url.endswith("/v1/query") for _, url, _ in transport.calls)
    assert not any("upgrade" in c for c in result["components"])
    assert result["options"]["upgrades"] is False and result["summary"]["upgrades"]["by_verdict"] == {}
    assert "fixed in 1.1 KEV" in render_summary(result) and "upgrades " not in render_summary(result)


def test_the_summary_counts_the_findings_it_does_not_list(tmp_path, delivery):
    result, _ = run(tmp_path, delivery, ScriptedTransport(routes()))
    lines = render_summary(result).splitlines()
    at = lines.index("vulns        2 distinct: critical 1, medium 1, known exploited 1")
    assert lines[at + 1].startswith("  critical CVE-2023-0001        org.example:lib 1.0, upgrade to 1.1")
    assert lines[at + 2] == "  ... medium 1 not listed here (vulnerabilities.csv)"
