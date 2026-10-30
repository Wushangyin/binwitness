"""Upgrade advice against real advisories and version lists (public OSV records and registry listings, trimmed:
see tests/data/upgrade/*.json "source")."""
import json
import re
from pathlib import Path

import pytest

from binwitness import upgrades
from binwitness.maven import CENTRAL
from binwitness.net import Net
from binwitness.upgrades import Listing, advise, context_caveats, is_published, line_of, published_versions

from helpers import ScriptedTransport

DATA = Path(__file__).parent / "data" / "upgrade"


def case(stem, version, **listing):
    data = json.loads((DATA / f"{stem}.json").read_text())
    found = Listing(data["versions"], frozenset(data["deprecated"]), {"source": "registry"}) if not listing else \
        Listing(**{"versions": data["versions"], **listing})
    return advise(data["ecosystem"], data["name"], version, data["records"], found)


def codes(block):
    return [c["code"] for c in block["caveats"]]


def advisory(osv_id, introduced, fixed, severity="HIGH", name="org.example:lib", ecosystem="Maven"):
    return {"id": osv_id, "database_specific": {"severity": severity},
            "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]}


def test_the_nearest_release_outside_every_advisory_on_the_same_line():
    block = case("netty-codec-http", "4.1.42.Final")
    assert (block["verdict"], block["target"]) == ("upgrade", "4.1.137.Final")
    assert len(block["clears"]) == 23 and block["remaining"] == [] == block["introduced"]
    # "4.1.44" in the advisories is the release published as 4.1.44.Final.
    assert block["fix_versions_not_published"] == []


def test_a_later_release_inside_a_newer_advisory_is_no_target():
    records = [advisory("GHSA-old", "0", "1.2"), advisory("GHSA-new", "1.2", "1.3")]
    block = advise("maven", "org.example:lib", "1.1", records, Listing(["1.0", "1.1", "1.2", "1.3"]))
    assert (block["verdict"], block["target"]) == ("upgrade", "1.3")
    # Mutation: judged by the advisories of the version in use alone, 1.2 would look fixed.
    alone = advise("maven", "org.example:lib", "1.1", records[:1], Listing(["1.0", "1.1", "1.2", "1.3"]))
    assert alone["target"] == "1.2"
    # Trading one high-severity advisory for another is no improvement; trading it for a low one is.
    swap = advise("maven", "org.example:lib", "1.1", records, Listing(["1.0", "1.1", "1.2"]))
    assert (swap["verdict"], swap["target"]) == ("no-published-fix", None)
    milder = [records[0], advisory("GHSA-new", "1.2", "1.3", "LOW")]
    partial = advise("maven", "org.example:lib", "1.1", milder, Listing(["1.0", "1.1", "1.2"]))
    assert (partial["verdict"], partial["target"]) == ("partial", "1.2")
    assert partial["clears"] == ["GHSA-old"] and partial["introduced"] == ["GHSA-new"]


def test_the_same_line_comes_first_and_a_later_major_is_flagged():
    block = case("spring-web", "5.3.31")
    assert (block["verdict"], block["target"]) == ("upgrade-across-major", "6.1.21")
    assert "compatibility-not-assessed" in codes(block)
    assert block["same_line"]["target"] == "5.3.38"
    # Fixed for the 5.x line only by moving to 6.0.0.
    assert "CVE-2016-1000027" in block["same_line"]["remaining"]
    assert "CVE-2016-1000027" in block["clears"]


def test_a_vendor_suffix_release_publishes_the_fix_the_advisory_names_by_number():
    block = case("jetty-server", "9.4.53.v20231009")
    assert block["same_line"]["target"] == "9.4.57.v20241219"
    assert block["fix_versions_not_published"] == []
    assert is_published("maven", "9.4.56", ["9.4.56.v20240826"])
    assert is_published("maven", "33.7.2", ["33.7.2-jre"])
    # Mutation: a later patch release does not publish an earlier number.
    assert not is_published("maven", "9.4.5", ["9.4.56.v20240826"])
    assert not is_published("maven", "1.2", ["1.2.1"])


def test_fixed_versions_that_were_never_published_are_listed():
    block = case("jetty-security", "9.4.53.v20231009")
    assert block["fix_versions_not_published"] == [{"id": "CVE-2026-10050", "fixed": f}
                                                   for f in ("9.4.63", "10.0.31", "11.0.31")]
    assert (block["verdict"], block["target"]) == ("upgrade-across-major", "12.0.36")


def test_no_published_version_of_the_coordinate_leaves_the_advisories():
    block = case("log4j", "1.2.17")
    assert (block["verdict"], block["target"]) == ("no-published-fix", None)
    assert len(block["remaining"]) == 6
    # "2.0" is a release of org.apache.logging.log4j, never of log4j:log4j.
    assert block["fix_versions_not_published"] == [{"id": "CVE-2023-26464", "fixed": "2.0"}]
    assert block["osv_fixed"] == {"CVE-2023-26464": ["2.0"]}


def test_a_version_list_from_the_local_index_cannot_prove_a_fix_unpublished():
    block = case("log4j", "1.2.17", source={"source": "local Maven Central hash index", "as_of": "2026-10-01"})
    assert block["verdict"] == "unverified" and block["target"] is None
    assert "(2.0) is not in the local hash index (as of 2026-10-01)" in block["reason"]
    found = case("netty-codec-http", "4.1.42.Final", source={"source": "local", "as_of": "2026-10-01"})
    assert found["verdict"] == "upgrade" and "local-version-list" in codes(found)


def test_variants_stay_variants():
    jre = case("guava", "31.1-jre")
    assert jre["target"] == "33.7.2-jre" and "flavor-choice" not in codes(jre)
    android = case("guava", "31.1-android")
    assert android["target"] == "33.7.2-android"
    # Before 22.0 Guava had one build; the fixed releases come in two, and the advice does not pick for the user.
    plain = case("guava", "20.0")
    assert {plain["target"], *plain["alternatives"]} == {"33.7.2-android", "33.7.2-jre"}
    choice = next(c for c in plain["caveats"] if c["code"] == "flavor-choice")
    assert "33.7.2-android, 33.7.2-jre" in choice["text"]


def test_an_underscore_suffix_is_a_variant_build_too():
    records = [advisory("GHSA-rce", "1.2.68", "0", name="com.alibaba:fastjson")]
    records[0]["affected"][0]["ranges"][0]["events"] = [{"introduced": "1.2.68"}, {"last_affected": "1.2.83"}]
    block = advise("maven", "com.alibaba:fastjson", "1.2.80", records,
                   Listing(["1.2.80", "1.2.83", "1.2.83_noneautotype"]))
    assert block["target"] == "1.2.83_noneautotype" and "flavor-choice" in codes(block)


def test_variant_rule_mutation_picks_the_other_platform(monkeypatch):
    monkeypatch.setattr(upgrades, "variant", lambda ecosystem, version: None)
    assert case("guava", "31.1-jre")["target"] == "33.7.2-android"


def test_a_suffix_that_graduates_away_is_still_followed():
    records = [advisory("GHSA-x", "0", "2.0.0")]
    block = advise("maven", "org.example:lib", "1.0.0-incubating", records,
                   Listing(["1.0.0-incubating", "1.1.0-incubating", "2.0.0"]))
    assert block["target"] == "2.0.0" and "flavor-dropped" in codes(block)


def test_deprecated_releases_are_skipped():
    block = case("lodash", "4.17.15")
    assert (block["verdict"], block["target"]) == ("upgrade", "4.18.1")
    assert case("lodash", "4.17.15", deprecated=frozenset())["target"] == "4.18.0"


def test_npm_zero_minor_versions_are_lines_of_their_own():
    zero = case("minimist", "0.0.8")
    assert (zero["verdict"], zero["target"]) == ("upgrade-across-major", "0.2.4")
    one = case("minimist", "1.2.0")
    assert (one["verdict"], one["target"]) == ("upgrade", "1.2.6")
    assert line_of("npm", "0.0.8") != line_of("npm", "0.2.4")
    assert line_of("maven", "0.9") == line_of("maven", "0.10")


def test_calendar_versions_are_one_line():
    records = [advisory("GHSA-json", "0", "20231013", name="org.json:json")]
    block = advise("maven", "org.json:json", "20180813", records, Listing(["20180813", "20230227", "20231013"]))
    assert (block["verdict"], block["target"]) == ("upgrade", "20231013")


def test_a_malicious_package_is_removed_not_upgraded():
    block = case("fs", "0.0.1-security")
    assert (block["verdict"], block["target"]) == ("remove-malicious", None)


def test_prereleases_only_when_already_on_one_and_otherwise_named():
    records = [advisory("GHSA-x", "0", "2.0.0-RC1")]
    listing = Listing(["1.0.0", "2.0.0-M1", "2.0.0-RC1"])
    block = advise("maven", "org.example:lib", "1.0.0", records, listing)
    assert block["verdict"] == "no-published-fix"
    assert next(c for c in block["caveats"] if c["code"] == "prerelease-only")["version"] == "2.0.0-RC1"
    on_milestone = advise("maven", "org.example:lib", "2.0.0-M1", records, listing)
    assert (on_milestone["verdict"], on_milestone["target"]) == ("upgrade", "2.0.0-RC1")


def test_the_severest_findings_weigh_first():
    records = [advisory("GHSA-crit", "0", "1.2", "CRITICAL"), advisory("GHSA-low1", "1.2", "9.0", "LOW"),
               advisory("GHSA-low2", "1.2", "9.0", "LOW"), advisory("GHSA-high", "0", "2.0", "HIGH")]
    block = advise("maven", "org.example:lib", "1.0", records, Listing(["1.0", "1.1", "1.2"]))
    assert (block["verdict"], block["target"]) == ("partial", "1.2")
    assert block["remaining"] == ["GHSA-high"] and block["introduced"] == ["GHSA-low1", "GHSA-low2"]


def test_findings_whose_ranges_cannot_be_read_never_count_as_fixed():
    records = [advisory("GHSA-a", "0", "1.2")]
    reported = {"GHSA-a": {"severity": "HIGH"}, "GHSA-odd": {"severity": "HIGH"}}
    block = advise("maven", "org.example:lib", "1.0", records, Listing(["1.0", "1.2"]), reported)
    assert block["verdict"] == "partial" and block["remaining"] == ["GHSA-odd"]
    assert "range-unreadable" in codes(block)
    alone = advise("maven", "org.example:lib", "1.0", [], Listing(["1.0", "1.2"]), {"GHSA-odd": {"severity": "HIGH"}})
    assert alone["verdict"] == "unverified" and "GHSA-odd" in alone["reason"]


def test_no_version_list_means_unverified_with_the_advisories_numbers():
    records = [advisory("GHSA-a", "0", "1.2")]
    block = advise("maven", "org.example:lib", "1.0", records, Listing(None, error="offline"))
    assert block["verdict"] == "unverified" and block["osv_fixed"] == {"GHSA-a": ["1.2"]}


def component(**extra):
    item = {"purl": "pkg:maven/org.example/lib@1.0", "contained_in": [], "files": [{"published": "identical"}],
            "confidence": "exact", "scope": "runtime", "vulnerabilities": ["CVE-1"]}
    return item | extra


def test_where_the_component_was_found_qualifies_the_advice():
    table = {"CVE-1": {"affects": {"pkg:maven/org.example/lib@1.0": {"fixed": ["1.2"]}}},
             "CVE-2": {"affects": {"pkg:maven/org.example/lib@1.0": {"fixed": ["3.0"],
                                                                     "via": "pkg:maven/org.other/lib@1.0"}}}}
    assert context_caveats(component(), table) == []
    embedded = context_caveats(component(contained_in=["host-2.0.jar"], files=[], confidence="declared"), table)
    assert [c["code"] for c in embedded] == ["embedded-in-host"] and "host-2.0.jar" in embedded[0]["text"]
    assert [c["code"] for c in context_caveats(component(files=[{"published": "differs"}]), table)] == ["modified-jar"]
    assert [c["code"] for c in context_caveats(component(confidence="declared"), table)] == ["coordinates-unverified"]
    assert [c["code"] for c in context_caveats(component(scope="dev"), table)] == ["dev-dependency"]
    via = context_caveats(component(vulnerabilities=["CVE-1", "CVE-2"]), table)
    assert [c["code"] for c in via] == ["via-alias"] and via[0]["via"] == "pkg:maven/org.other/lib@1.0"


# Our own wording: package names such as safe-buffer or clean-css are data, not claims.
FORBIDDEN = re.compile(r"\b(safe|safely|clean|secure)\b|no (known )?vulnerabilit", re.I)


@pytest.mark.parametrize("text", [*upgrades.VERDICT_TEXT.values(), *upgrades.CAVEATS.values()])
def test_the_advice_never_vouches_for_a_version(text):
    assert not FORBIDDEN.search(text)


class IndexOnly:
    """A local store holding only the hash index, with these versions of every artifact."""

    def __init__(self, versions):
        self.versions = versions

    def has(self, name):
        return name == "maven-hashes"

    def maven_versions(self, group, artifact):
        return self.versions

    def data_as_of(self, name):
        return "2026-10-01T00:00:00Z"


def metadata(*versions):
    listed = "".join(f"<version>{v}</version>" for v in versions)
    return f"<metadata><versioning><versions>{listed}</versions></versioning></metadata>".encode()


def test_the_registry_is_asked_only_when_the_local_index_lacks_a_fixed_version(tmp_path):
    transport = ScriptedTransport({"maven-metadata.xml": metadata("1.0", "1.1", "1.2")})
    net = Net(cache_dir=tmp_path / "cache", transport=transport)
    local = published_versions(net, IndexOnly(["1.0", "1.1"]), "maven", "org.example:lib", expected=("1.1",))
    assert transport.calls == [] and local.source["as_of"] == "2026-10-01T00:00:00Z"
    online = published_versions(net, IndexOnly(["1.0"]), "maven", "org.example:lib", expected=("1.1",))
    assert [url for _, url, _ in transport.calls] == [f"{CENTRAL}/org/example/lib/maven-metadata.xml"]
    assert online.versions == ["1.0", "1.1", "1.2"] and online.source["source"] == "maven-metadata.xml"
    # Offline, the index is what there is; the advice then says what it cannot tell (see the log4j case).
    offline = Net(cache_dir=tmp_path / "empty", offline=True, transport=transport)
    assert published_versions(offline, IndexOnly(["1.0"]), "maven", "org.example:lib", expected=("1.1",)).source["as_of"]
    assert published_versions(offline, None, "maven", "org.example:lib").error == \
        "maven-metadata.xml: not in the cache (offline)"


def test_version_lists_come_through_the_mirror_and_the_extra_repositories(tmp_path):
    transport = ScriptedTransport({"mirror.example/central/org/example/lib/": metadata("1.0", "1.1"),
                                   "milestones.example/org/example/lib/": metadata("1.2-M1", "1.1"),
                                   "repo1.maven.org": None})
    net = Net(cache_dir=tmp_path, transport=transport, mirrors={CENTRAL: "https://mirror.example/central"})
    found = published_versions(net, None, "maven", "org.example:lib", ("https://milestones.example",))
    assert found.versions == ["1.0", "1.1", "1.2-M1"]
    assert not any("repo1.maven.org" in url for _, url, _ in transport.calls)


def test_npm_versions_and_deprecations_come_from_the_abbreviated_document(tmp_path):
    document = {"name": "@scope/pkg", "versions": {"1.0.0": {}, "1.0.1": {"deprecated": "broken"}, "1.0.2": {}}}
    transport = ScriptedTransport({"registry.npmjs.org/@scope%2Fpkg": document})
    found = published_versions(Net(cache_dir=tmp_path, transport=transport), None, "npm", "@scope/pkg")
    assert found.versions == ["1.0.0", "1.0.1", "1.0.2"] and found.deprecated == {"1.0.1"}
    missing = published_versions(Net(cache_dir=tmp_path / "x", transport=ScriptedTransport({})), None, "npm", "nope")
    assert missing.versions is None and missing.error == "not in the npm registry"


def test_variant_builds_that_do_equally_well_are_both_named_in_the_text():
    from binwitness.output import upgrade_text
    plain = case("guava", "20.0")
    assert upgrade_text(plain).startswith("upgrade-across-major 33.7.2-android or 33.7.2-jre")
    assert upgrade_text(case("guava", "31.1-jre")) == "upgrade-across-major 33.7.2-jre"


def record(osv_id, name, events, severity="HIGH"):
    return {"id": osv_id, "database_specific": {"severity": severity},
            "affected": [{"package": {"ecosystem": "Maven", "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


class Store:
    """Local datasets: OSV records and the hash index's versions per package."""

    def __init__(self, records, versions):
        self.records, self.versions = records, versions

    def has(self, name):
        return name in ("osv-maven", "maven-hashes")

    def osv_records(self, ecosystem, name):
        return [r for r in self.records if any(a["package"]["name"] == name for a in r["affected"])]

    def maven_versions(self, group, artifact):
        return self.versions.get(f"{group}:{artifact}", [])

    def data_as_of(self, name):
        return "2026-10-01T00:00:00Z"


def item(name, version, findings=(), **extra):
    group, artifact = name.split(":")
    return {"purl": f"pkg:maven/{group}/{artifact}@{version}", "ecosystem": "maven", "name": name,
            "version": version, "vulnerabilities": list(findings), "contained_in": [], "files": [{"published": "yes"}],
            "confidence": "exact", "scope": "runtime"} | extra


def table_for(items):
    table = {}
    for i in items:
        for key in i["vulnerabilities"]:
            table.setdefault(key, {"severity": "HIGH", "malicious": False, "affects": {}})["affects"][i["purl"]] = \
                {"fixed": []}
    return table


FAMILY_RECORDS = [record("CVE-2026-0001", "org.example:core", [{"introduced": "0"}, {"fixed": "1.1"}]),
                  record("CVE-2026-0002", "org.example:web", [{"introduced": "0"}, {"fixed": "1.3"}]),
                  # Only the member without findings has this one, and only from 1.2 on.
                  record("CVE-2026-0003", "org.example:jdbc", [{"introduced": "1.2"}, {"fixed": "1.4"}])]


def family_scan(tmp_path, jdbc_versions):
    versions = {"org.example:core": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5"],
                "org.example:web": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5"], "org.example:jdbc": jdbc_versions}
    items = [item("org.example:core", "1.0", ["CVE-2026-0001"]), item("org.example:web", "1.0", ["CVE-2026-0002"]),
             item("org.example:jdbc", "1.0"), item("org.other:lib", "1.0")]
    families = []
    net = Net(cache_dir=tmp_path, offline=True, transport=ScriptedTransport({}))
    upgrades.attach(net, Store(FAMILY_RECORDS, versions), items, table_for(items), families=families)
    return {i["name"]: i for i in items}, families


def test_artifacts_of_one_release_get_one_target_that_suits_them_all(tmp_path):
    named, families = family_scan(tmp_path, ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5"])
    # Each alone: core 1.1, web 1.3; 1.3 puts jdbc inside an advisory of its own, so together it is 1.4.
    assert (named["org.example:core"]["upgrade"]["target"], named["org.example:web"]["upgrade"]["target"]) == \
        ("1.1", "1.3")
    [family] = families
    assert (family["family"], family["verdict"], family["target"]) == ("org.example@1.0", "upgrade", "1.4")
    assert family["clears"] == ["CVE-2026-0001", "CVE-2026-0002"] and family["introduced"] == []
    assert family["members"] == ["pkg:maven/org.example/core@1.0", "pkg:maven/org.example/jdbc@1.0",
                                 "pkg:maven/org.example/web@1.0"]
    assert {m["component"]: m["own_target"] for m in family["per_member"]}["pkg:maven/org.example/jdbc@1.0"] is None
    assert all(named[n]["upgrade_family"] == "org.example@1.0" for n in ("org.example:core", "org.example:jdbc"))
    assert "upgrade_family" not in named["org.other:lib"] and "upgrade" not in named["org.example:jdbc"]


def test_a_member_that_stops_being_published_bounds_the_family(tmp_path):
    _, [family] = family_scan(tmp_path, ["1.0", "1.1", "1.2", "1.3"])
    assert (family["verdict"], family["target"], family["remaining"]) == ("partial", "1.1", ["CVE-2026-0002"])
    ends = next(c for c in family["caveats"] if c["code"] == "family-ends")
    assert ends["members"] == "pkg:maven/org.example/jdbc@1.0" and ends["latest"] == "1.5"


def test_family_mutation_without_the_quiet_member_lands_inside_its_advisory(tmp_path, monkeypatch):
    real = upgrades._families
    monkeypatch.setattr(upgrades, "_families", lambda items, table: {
        k: [m for m in v if m["vulnerabilities"]] for k, v in real(items, table).items()})
    _, [family] = family_scan(tmp_path, ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5"])
    assert family["target"] == "1.3"


def pom(relocated_to=None):
    inner = f"<relocation><groupId>{relocated_to}</groupId></relocation>" if relocated_to else ""
    return f"<project><distributionManagement>{inner}</distributionManagement></project>".encode()


def relocation_scan(tmp_path, relocated_to):
    records = [record("CVE-2026-0010", "org.example:connector", [{"introduced": "0"}, {"fixed": "1.1"}]),
               # Never fixed under the old name: the fix came out after the move.
               record("CVE-2026-0011", "org.example:connector", [{"introduced": "0"}]),
               record("GHSA-new1-0011", "org.moved:connector", [{"introduced": "0"}, {"fixed": "1.3"}])]
    records[2]["aliases"] = ["CVE-2026-0011"]
    # The hash index has jars only: not 1.2, a POM that relocates the artifact. The repository lists it.
    versions = {"org.example:connector": ["1.0", "1.1"], "org.moved:connector": ["1.2", "1.3", "2.0"]}
    transport = ScriptedTransport({"org/example/connector/maven-metadata.xml": metadata("1.0", "1.1", "1.2"),
                                   "org/example/connector/1.2/connector-1.2.pom": pom(relocated_to)})
    items = [item("org.example:connector", "1.0", ["CVE-2026-0010", "CVE-2026-0011"])]
    upgrades.attach(Net(cache_dir=tmp_path, transport=transport), Store(records, versions), items, table_for(items))
    return items[0]["upgrade"]


def test_a_relocated_artifact_is_followed_to_its_new_coordinates(tmp_path):
    from binwitness.output import finding_advice, upgrade_text
    block = relocation_scan(tmp_path, "org.moved")
    assert (block["verdict"], block["target_package"], block["target"]) == ("relocated", "org.moved:connector", "1.3")
    assert block["clears"] == ["CVE-2026-0010", "CVE-2026-0011"] and block["remaining"] == []
    assert block["same_coordinates"]["verdict"] == "partial" and block["same_coordinates"]["target"] == "1.1"
    assert "relocated" in codes(block) and "org.example:connector 1.2" in block["caveats"][-1]["text"]
    assert upgrade_text(block) == "relocated org.moved:connector 1.3"
    assert finding_advice({"upgrade": block, "ecosystem": "maven", "version": "1.0"}, "CVE-2026-0011",
                          {"fixed": []}) == ", move to org.moved:connector 1.3"


def test_without_a_relocation_the_advice_stays_on_the_coordinates(tmp_path):
    block = relocation_scan(tmp_path, None)
    assert (block["verdict"], block["target"], block["remaining"]) == ("partial", "1.1", ["CVE-2026-0011"])


def declared(family, *names):
    return {"names": list(names), "family": family}


MIT, LGPL = declared("permissive", "MIT"), declared("weak-copyleft", "LGPL-2.1")


def test_a_target_under_a_more_restrictive_license_is_called_out():
    licensed = {("maven", "org.example:connector", "1.0"): LGPL,
                ("maven", "org.moved:connector", "2.0"): declared("strong-copyleft", "AGPL-3.0"),
                ("maven", "org.example:same", "1.0"): MIT, ("maven", "org.example:same", "1.1"): MIT,
                ("maven", "org.example:freer", "1.0"): LGPL, ("maven", "org.example:freer", "1.1"): MIT,
                ("maven", "org.example:odd", "1.0"): MIT,
                ("maven", "org.example:odd", "1.1"): {"expressions": ["LicenseRef-Proprietary"], "family": "unknown"},
                # The target's license cannot be read, or the one in use is not classified: nothing to compare.
                ("maven", "org.example:unread", "1.0"): MIT,
                ("maven", "org.example:untold", "1.0"): declared("unknown", "Custom")}
    moved = {"target": "2.0", "target_package": "org.moved:connector"}
    # A license read from inside the jar is not compared: it may be a bundled library's.
    items = [item("org.example:connector", "1.0", ["X"], license=declared("strong-copyleft", "GPL-3.0"),
                  upgrade={**moved, "caveats": []}),
             item("org.example:same", "1.0", ["X"], license=LGPL, upgrade={"target": "1.1", "caveats": []}),
             item("org.example:freer", "1.0", ["X"], upgrade={"target": "1.1", "caveats": []}),
             item("org.example:odd", "1.0", ["X"], upgrade={"target": "1.1", "caveats": []}),
             item("org.example:unread", "1.0", ["X"], upgrade={"target": "1.1", "caveats": []}),
             item("org.example:untold", "1.0", ["X"], upgrade={**moved, "caveats": []})]
    upgrades.note_license_changes(items, [], lambda *key: licensed.get(key))
    assert {i["name"]: codes(i["upgrade"]) for i in items} == {
        "org.example:connector": ["license-changes"], "org.example:same": [], "org.example:freer": [],
        "org.example:odd": ["license-changes"], "org.example:unread": [], "org.example:untold": []}
    [change] = items[0]["upgrade"]["caveats"]
    assert change["text"] == ("the target is licensed differently: org.moved:connector 2.0 AGPL-3.0 (strong-copyleft) "
                              "against org.example:connector 1.0 LGPL-2.1 (weak-copyleft); read the new terms before "
                              "upgrading")


def test_a_release_family_names_the_members_whose_license_tightens():
    members = [item("org.example:core", "1.0", ["X"]), item("org.example:web", "1.0"), item("org.example:cli", "1.0")]
    family = {"family": "org.example@1.0", "members": [m["purl"] for m in members], "target": "2.0", "caveats": []}
    tighter = declared("source-available", "BUSL-1.1")
    licensed = {**{("maven", m["name"], "1.0"): MIT for m in members},
                ("maven", "org.example:core", "2.0"): MIT, ("maven", "org.example:web", "2.0"): tighter,
                ("maven", "org.example:cli", "2.0"): tighter}
    upgrades.note_license_changes(members, [family], lambda *key: licensed.get(key))
    [change] = family["caveats"]
    assert [c["package"] for c in change["changes"]] == ["org.example:web", "org.example:cli"]
    assert change["text"] == ("the target is licensed differently: org.example:web, org.example:cli 2.0 BUSL-1.1 "
                              "(source-available) against 1.0 MIT (permissive); read the new terms before upgrading")
