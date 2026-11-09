"""The dependency graph (what each delivered jar depends on among the jars delivered with it) and SPDX output."""
import base64
import hashlib

import pytest

from binwitness.dependencies import declared, unit
from binwitness.licenses import is_spdx_expression
from binwitness.net import Net
from binwitness.output import cyclonedx, render_summary, spdx, write_all
from binwitness.scan import Options, scan

from helpers import ScriptedTransport, Served, make_jar, make_zip


def pom(group, artifact, *needs, extra=""):
    listed = "".join(f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>"
                     + (f"<scope>{s[0]}</scope>" if s else "") + "</dependency>" for g, a, *s in needs)
    return (f"<project><groupId>{group}</groupId><artifactId>{artifact}</artifactId>{extra}"
            f"<dependencies>{listed}</dependencies></project>")


def library(group, artifact, version, *needs, own_pom=True):
    extra = {f"org/{artifact}/Main.class": f"\xca\xfe {artifact} {version}"}
    if own_pom:
        extra[f"META-INF/maven/{group}/{artifact}/pom.xml"] = pom(group, artifact, *needs)
    return make_jar(group, artifact, version, extra)


def known(data, name, version, licenses=("Apache-2.0",), also=()):
    """deps.dev knows this file (under ``also`` too): it is identified by its hash."""
    encoded = base64.b64encode(hashlib.sha1(data).digest()).decode()
    encoded = encoded.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    return {f"hash.value={encoded}": {"results": [{"version": {
        "versionKey": {"system": "MAVEN", "name": n, "version": version}, "licenses": list(licenses)}}
        for n in (name, *also)]}}


QUIET = {"hash.value=": {"results": []}, "solrsearch": {"response": {"docs": []}},
         "querybatch": {"results": []}, "/systems/maven/packages/": {"licenses": ["Apache-2.0"]}}


def scan_of(tmp_path, files, table, offline=False, cache="cache"):
    path = tmp_path / "delivery.zip"
    path.write_bytes(make_zip(files))
    transport = ScriptedTransport({**table, **QUIET})
    net = Net(cache_dir=tmp_path / cache, transport=transport, sleep=lambda s: None, offline=offline)
    return scan([path], net, Options(first_party_groups=("com.acme",), scan_js=False), log=lambda m: None), transport


REZIPPED_POM = "groupId=org.example\nartifactId=rezipped\nversion=3.0\n"
REZIPPED = {"org/example/Lib.class": b"\xca\xfe\xba\xbe" + bytes(range(256)) * 4, "org/example/messages.txt": "hello"}


def sha1(data):
    return hashlib.sha1(data).hexdigest()


# --- what a POM declares -------------------------------------------------------------------------------------

def test_a_pom_declares_its_projects_own_dependencies_and_not_the_others_it_mentions():
    text = """<project>
      <parent><groupId>org.parent</groupId><artifactId>parent</artifactId><version>1</version></parent>
      <artifactId>child</artifactId>
      <properties><netty.group>io.netty</netty.group></properties>
      <!-- <dependency><groupId>x</groupId><artifactId>commented-out</artifactId></dependency> -->
      <dependencyManagement><dependencies>
        <dependency><groupId>m</groupId><artifactId>managed</artifactId></dependency>
      </dependencies></dependencyManagement>
      <dependencies>
        <dependency><groupId>${project.groupId}</groupId><artifactId>sibling</artifactId></dependency>
        <dependency><groupId>${netty.group}</groupId><artifactId>netty-buffer</artifactId>
          <exclusions><exclusion><groupId>e</groupId><artifactId>excluded</artifactId></exclusion></exclusions>
        </dependency>
        <dependency><groupId>${grandparent.group}</groupId><artifactId>loose</artifactId></dependency>
        <dependency><groupId>junit</groupId><artifactId>junit</artifactId><scope>test</scope></dependency>
        <dependency><groupId>javax.servlet</groupId><artifactId>servlet-api</artifactId><scope>provided</scope>
        </dependency>
        <dependency><groupId>o</groupId><artifactId>${unknown.artifact}</artifactId></dependency>
        <dependency><groupId>org.parent</groupId><artifactId>sibling</artifactId></dependency>
        <dependency><exclusions><exclusion><groupId>e</groupId><artifactId>excluded-first</artifactId></exclusion>
          </exclusions><groupId>org.later</groupId><artifactId>after-exclusions</artifactId></dependency>
      </dependencies>
      <build><plugins><plugin><dependencies>
        <dependency><groupId>b</groupId><artifactId>plugin-classpath</artifactId></dependency>
      </dependencies></plugin></plugins></build>
      <profiles><profile><dependencies>
        <dependency><groupId>p</groupId><artifactId>profiled</artifactId></dependency>
      </dependencies></profile></profiles>
    </project>"""
    assert declared(text) == ["org.parent:sibling", "io.netty:netty-buffer", "${grandparent.group}:loose",
                              "javax.servlet:servlet-api", "org.later:after-exclusions"]


def test_a_projects_own_group_wins_over_its_parents():
    text = ("<project><parent><groupId>org.parent</groupId></parent><groupId>org.own</groupId>"
            "<dependencies><dependency><groupId>${project.groupId}</groupId><artifactId>a</artifactId></dependency>"
            "<dependency><groupId>${project.parent.groupId}</groupId><artifactId>b</artifactId></dependency>"
            "</dependencies></project>")
    assert declared(text) == ["org.own:a", "org.parent:b"]


@pytest.mark.parametrize("location, expected", [
    ("app.war!/WEB-INF/lib/a.jar", "app.war"),
    ("dist.zip!/app.jar!/BOOT-INF/lib/a.jar", "dist.zip!/app.jar"),
    ("image.tar!/<example/app:1.0>/opt/lib/a.jar", "image.tar!/<example/app:1.0>"),
    ("image.tar!/<example/app:1.0>/opt/app.war!/WEB-INF/lib/a.jar", "image.tar!/<example/app:1.0>/opt/app.war"),
    ("delivery/rootfs/<example/app:1.0>/opt/lib/a.jar", "delivery/rootfs/<example/app:1.0>"),
    ("delivery/lib/optional/a.jar", "delivery"),
    ("a.jar", ""),
])
def test_a_jar_is_delivered_with_the_jars_of_its_innermost_archive(location, expected):
    assert unit(location) == expected


# --- the graph ------------------------------------------------------------------------------------------------

CORE = library("org.example", "core", "1.0", ("org.example", "codec"), ("org.example", "absent"),
               ("junit", "junit", "test"))
CODEC = library("org.example", "codec", "1.0")
JUNIT = library("junit", "junit", "4.13")
OTHER_CODEC = library("org.example", "codec", "2.0")
SERVICE = library("com.acme", "service", "1.0", ("org.example", "core"))


def graph_scan(tmp_path, **kwargs):
    app = make_zip({"WEB-INF/lib/core-1.0.jar": CORE, "WEB-INF/lib/codec-1.0.jar": CODEC,
                    "WEB-INF/lib/junit-4.13.jar": JUNIT, "WEB-INF/lib/service-1.0.jar": SERVICE})
    table = {**known(CORE, "org.example:core", "1.0"), **known(CODEC, "org.example:codec", "1.0"),
             **known(JUNIT, "junit:junit", "4.13"), **known(OTHER_CODEC, "org.example:codec", "2.0")}
    # Another application of the delivery has its own codec: core does not depend on that one.
    other = make_zip({"WEB-INF/lib/codec-2.0.jar": OTHER_CODEC})
    return scan_of(tmp_path, {"app.war": app, "other.war": other}, table, **kwargs)


def test_a_jar_depends_on_the_jars_its_pom_declares_that_are_delivered_with_it(tmp_path):
    result, _ = graph_scan(tmp_path)
    by_name = {c["name"]: c for c in result["components"]}
    # The undelivered one is not there; the test one is delivered but not depended on; the codec of the other
    # war is not.
    assert by_name["org.example:core"]["depends_on"] == ["pkg:maven/org.example/codec@1.0"]
    assert by_name["org.example:codec"]["depends_on"] == []
    (service,) = result["first_party"]
    assert service["depends_on"] == ["pkg:maven/org.example/core@1.0"]
    assert service["dependencies"] == {"source": "jar: pom.xml", "declared": ["org.example:core"]}
    assert result["summary"]["dependencies"] == {"jars": 5, "declared_in_jar": 5, "from_published_pom": 0,
                                                 "not_known": 0, "edges": 2}


def test_a_spring_boot_jar_depends_on_the_jars_it_carries(tmp_path):
    boot = make_zip({"META-INF/maven/com.acme/boot/pom.xml": pom("com.acme", "boot", ("org.example", "codec")),
                     "META-INF/maven/com.acme/boot/pom.properties": "groupId=com.acme\nartifactId=boot\nversion=1\n",
                     "BOOT-INF/lib/codec-1.0.jar": CODEC})
    result, _ = scan_of(tmp_path, {"boot.jar": boot}, known(CODEC, "org.example:codec", "1.0"))
    (own,) = result["first_party"]
    assert own["depends_on"] == ["pkg:maven/org.example/codec@1.0"]


def test_a_group_left_to_a_parents_property_matches_by_artifact_when_only_one_jar_has_it(tmp_path):
    loose = library("org.example", "loose", "1.0", ("${netty.group}", "codec"), ("${netty.group}", "core"))
    other_core = library("org.other", "core", "1.0")
    table = {**known(loose, "org.example:loose", "1.0"), **known(CODEC, "org.example:codec", "1.0"),
             **known(CORE, "org.example:core", "1.0"), **known(other_core, "org.other:core", "1.0")}
    result, _ = scan_of(tmp_path, {"lib/loose.jar": loose, "lib/codec.jar": CODEC, "lib/core.jar": CORE,
                                   "lib/other-core.jar": other_core}, table)
    by_name = {c["name"]: c for c in result["components"]}
    # Two jars are named core: which one is meant is not known.
    assert by_name["org.example:loose"]["depends_on"] == ["pkg:maven/org.example/codec@1.0"]


GRADLE = library("org.example", "gradle-built", "1.0", own_pom=False)
GRADLE_POM = "/org/example/gradle-built/1.0/gradle-built-1.0.pom"
GRADLE_FILES = {"lib/gradle-built-1.0.jar": GRADLE, "lib/codec-1.0.jar": CODEC}
GRADLE_TABLE = {**known(GRADLE, "org.example:gradle-built", "1.0"), **known(CODEC, "org.example:codec", "1.0")}


def test_a_jar_does_not_depend_on_itself_under_its_other_coordinate(tmp_path):
    # A relocated library: the old coordinate's POM depends on the new one, which is the same file.
    relocated = library("org.old", "lib", "2.0", ("org.new", "lib"))
    result, _ = scan_of(tmp_path, {"lib/lib-2.0.jar": relocated},
                        known(relocated, "org.new:lib", "2.0", also=("org.old:lib",)))
    (component,) = result["components"]
    assert component["files"][0]["also_published_as"]
    assert component["depends_on"] == []


def test_a_jar_without_a_pom_of_its_own_takes_the_dependencies_of_its_published_pom(tmp_path):
    table = {**GRADLE_TABLE, GRADLE_POM: pom("org.example", "gradle-built", ("org.example", "codec")).encode()}
    result, transport = scan_of(tmp_path, GRADLE_FILES, table)
    by_name = {c["name"]: c for c in result["components"]}
    assert by_name["org.example:gradle-built"]["depends_on"] == ["pkg:maven/org.example/codec@1.0"]
    (file,) = by_name["org.example:gradle-built"]["files"]
    assert file["dependencies"] == {"source": "Maven Central POM", "declared": ["org.example:codec"]}
    assert result["summary"]["dependencies"]["from_published_pom"] == 1
    assert "dependencies_not_read" not in result["summary"]["incomplete"]
    assert sum("gradle-built-1.0.pom" in url for _, url, _ in transport.calls) == 1


def test_a_published_pom_not_read_leaves_the_dependencies_unknown_and_says_why(tmp_path):
    failing, _ = scan_of(tmp_path, GRADLE_FILES, {**GRADLE_TABLE, GRADLE_POM: (500, b"")})
    by_name = {c["name"]: c for c in failing["components"]}
    assert by_name["org.example:gradle-built"]["depends_on"] is None
    assert failing["summary"]["incomplete"]["dependencies_not_read"] == 1
    (said,) = [w for w in failing["warnings"] if w.startswith("dependencies not known")]
    assert "could not be read (org.example:gradle-built:1.0" in said

    # Offline, with what that scan cached: the POM is not there.
    offline, _ = scan_of(tmp_path, GRADLE_FILES, GRADLE_TABLE, offline=True)
    assert offline["summary"]["dependencies"]["not_known"] == 1
    assert offline["summary"]["incomplete"]["dependencies_not_read"] == 1
    assert [w for w in offline["warnings"] if w.startswith("dependencies not known")] == [
        "dependencies not known for 1 jar without a pom.xml of their own: the published POM is not in the cache, "
        "and this scan does not go online"]
    assert "dependencies not read for 1 jars" in render_summary(offline)


def test_a_jar_known_only_by_what_it_declares_is_not_given_its_published_pom(tmp_path):
    # Not the published file: what was published under that name says nothing about this one.
    rebuilt = library("org.example", "rebuilt", "1.0", own_pom=False)
    table = {"/org/example/rebuilt/1.0/rebuilt-1.0.pom": pom("org.example", "rebuilt").encode()}
    result, _ = scan_of(tmp_path, {"lib/rebuilt-1.0.jar": rebuilt}, table)
    (component,) = result["components"]
    assert component["name"] == "org.example:rebuilt" and component["confidence"] not in ("exact", "content")
    assert component["depends_on"] is None and "dependencies" not in component["files"][0]


def test_a_pom_xml_that_cannot_be_read_says_nothing_about_dependencies(tmp_path):
    damaged = make_jar("org.example", "damaged", "1.0", {"META-INF/maven/org.example/damaged/pom.xml": b"\x00\x01"})
    result, _ = scan_of(tmp_path, {"lib/damaged-1.0.jar": damaged}, known(damaged, "org.example:damaged", "1.0"))
    (component,) = result["components"]
    assert component["depends_on"] is None
    assert result["summary"]["dependencies"]["not_known"] == 1


def test_the_dependencies_a_shaded_librarys_pom_declares_are_not_the_jars(tmp_path):
    # The only pom.properties names a library the jar bundles: its pom.xml is that library's, as is the license.
    release = make_zip({"META-INF/": b"", "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nBundle-Version: 3.0\r\n\r\n",
                        "META-INF/maven/org.example/rezipped/pom.properties": REZIPPED_POM, "org/": b"",
                        "org/example/": b"", **REZIPPED})
    host = make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
                     "META-INF/maven/org.example/rezipped/pom.properties": REZIPPED_POM,
                     "META-INF/maven/org.example/rezipped/pom.xml": pom("org.example", "rezipped",
                                                                         ("org.example", "core")),
                     **{f"com/host/C{i}.class": bytes([i]) for i in range(10)},
                     "com/host/internal/example/Lib.class": REZIPPED["org/example/Lib.class"]})
    table = {"/org/example/rezipped/3.0/rezipped-3.0.jar.sha1": b"0123456789abcdef0123456789abcdef01234567",
             "/org/example/rezipped/3.0/rezipped-3.0.jar": Served(release), **known(CORE, "org.example:core", "1.0")}
    result, _ = scan_of(tmp_path, {"lib/kxvw-4.1.0.jar": host, "lib/core-1.0.jar": CORE}, table)
    (unidentified,) = result["unidentified"]
    assert unidentified["embedded_coordinates"] == ["org.example:rezipped:3.0"]
    assert unidentified["depends_on"] is None and "dependencies" not in unidentified
    # In SPDX the library is in the jar it is shaded into.
    document = spdx(result)
    name = {p["SPDXID"]: p["name"] for p in document["packages"]}
    assert ("kxvw-4.1.0.jar", "org.example:rezipped") in {
        (name[r["spdxElementId"]], name[r["relatedSpdxElement"]]) for r in document["relationships"]
        if r["relationshipType"] == "CONTAINS"}


# --- CycloneDX ------------------------------------------------------------------------------------------------

def test_cyclonedx_lists_known_dependencies_and_what_each_input_holds(tmp_path):
    unknown = library("org.example", "unknown", "1.0", own_pom=False)
    app = make_zip({"WEB-INF/lib/core-1.0.jar": CORE, "WEB-INF/lib/codec-1.0.jar": CODEC,
                    "WEB-INF/lib/unknown-1.0.jar": unknown})
    table = {**known(CORE, "org.example:core", "1.0"), **known(CODEC, "org.example:codec", "1.0"),
             **known(unknown, "org.example:unknown", "1.0")}
    result, _ = scan_of(tmp_path, {"app.war": app}, table)
    bom = cyclonedx(result)
    ref = {c["name"]: c["bom-ref"] for c in bom["components"]}
    graph = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert graph[ref["core"]] == [ref["codec"]]
    assert graph[ref["codec"]] == []
    # Not listed means not known; an empty list would claim it depends on nothing.
    assert ref["unknown"] not in graph
    root = bom["metadata"]["component"]["bom-ref"]
    assert graph[root] == sorted([ref["core"], ref["unknown"]])
    assert set(graph) <= {c["bom-ref"] for c in bom["components"]} | {root}
    assert list(bom).index("dependencies") < list(bom).index("vulnerabilities")


# --- SPDX -----------------------------------------------------------------------------------------------------

def test_spdx_contains_follows_where_each_file_was_found_and_depends_on_the_graph(tmp_path):
    result, _ = graph_scan(tmp_path)
    document = spdx(result)
    paths = write_all(result, tmp_path / "out")
    assert tmp_path / "out" / "sbom.spdx.json" in paths
    assert document["spdxVersion"] == "SPDX-2.3" and document["dataLicense"] == "CC0-1.0"
    assert document["documentNamespace"].startswith("https://spdx.org/spdxdocs/binwitness-")
    ids = [p["SPDXID"] for p in document["packages"]]
    assert len(ids) == len(set(ids))
    name = {p["SPDXID"]: p.get("versionInfo") and f"{p['name']}@{p['versionInfo']}" or p["name"]
            for p in document["packages"]}
    relations = {(name.get(r["spdxElementId"], r["spdxElementId"]), r["relationshipType"],
                  name[r["relatedSpdxElement"]]) for r in document["relationships"]}
    assert ("SPDXRef-DOCUMENT", "DESCRIBES", "delivery.zip") in relations
    assert ("delivery.zip", "CONTAINS", "org.example:core@1.0") in relations
    assert ("org.example:core@1.0", "DEPENDS_ON", "org.example:codec@1.0") in relations
    assert ("service-1.0.jar", "DEPENDS_ON", "org.example:core@1.0") in relations
    assert ("org.example:core@1.0", "DEPENDS_ON", "org.example:codec@2.0") not in relations
    contained = {r["relatedSpdxElement"] for r in document["relationships"] if r["relationshipType"] in
                 ("CONTAINS", "DESCRIBES")}
    assert contained == set(ids)
    core = next(p for p in document["packages"] if p.get("versionInfo") == "1.0" and p["name"] == "org.example:core")
    assert core["checksums"][0] == {"algorithm": "SHA1", "checksumValue": sha1(CORE)}
    assert core["externalRefs"][0]["referenceLocator"] == "pkg:maven/org.example/core@1.0"
    assert core["licenseDeclared"] == "Apache-2.0"


def test_spdx_nests_a_jar_in_the_jar_that_carries_it(tmp_path):
    boot = make_zip({"META-INF/maven/com.acme/boot/pom.xml": pom("com.acme", "boot"),
                     "META-INF/maven/com.acme/boot/pom.properties": "groupId=com.acme\nartifactId=boot\nversion=1\n",
                     "BOOT-INF/lib/codec-1.0.jar": CODEC})
    result, _ = scan_of(tmp_path, {"boot.jar": boot}, known(CODEC, "org.example:codec", "1.0"))
    document = spdx(result)
    name = {p["SPDXID"]: p["name"] for p in document["packages"]}
    assert {(name[r["spdxElementId"]], name[r["relatedSpdxElement"]]) for r in document["relationships"]
            if r["relationshipType"] == "CONTAINS"} == {("delivery.zip", "boot.jar"), ("boot.jar", "org.example:codec")}


@pytest.mark.parametrize("licenses, declared_as, extracted", [
    (["Apache-2.0"], "Apache-2.0", []),
    (["MIT", "Apache-2.0"], "MIT OR Apache-2.0", []),
    (["GPL-2.0-with-classpath-exception"], "GPL-2.0 WITH Classpath-exception-2.0", []),
    (["MIT AND BSD-3-Clause", "Apache-2.0"], "(MIT AND BSD-3-Clause) OR Apache-2.0", []),
    # A reference SPDX tools would look for among the document's declarations.
    (["Apache-2.0 AND LicenseRef-vendor"], "LicenseRef-Apache-2.0-AND-LicenseRef-vendor",
     ["Apache-2.0 AND LicenseRef-vendor"]),
])
def test_spdx_license_declared_is_an_expression_spdx_tools_read(tmp_path, licenses, declared_as, extracted):
    result, _ = scan_of(tmp_path, {"lib/codec-1.0.jar": CODEC}, known(CODEC, "org.example:codec", "1.0", licenses))
    document = spdx(result)
    (package,) = [p for p in document["packages"] if p["name"] == "org.example:codec"]
    assert package["licenseDeclared"] == declared_as
    assert [e["extractedText"] for e in document.get("hasExtractedLicensingInfos", [])] == extracted


def test_a_license_name_without_an_spdx_id_is_carried_as_a_license_ref():
    from binwitness.output import _spdx_license
    extracted = {}
    assert _spdx_license({"names": ["Bouncy Castle"], "source": "jar: pom.xml"}, extracted) == \
        "LicenseRef-Bouncy-Castle"
    assert _spdx_license({"names": ["Bouncy Castle", "MIT"], "source": "Maven Central POM"},
                         extracted) == "LicenseRef-Bouncy-Castle OR MIT"
    assert list(extracted) == ["LicenseRef-Bouncy-Castle"]
    assert extracted["LicenseRef-Bouncy-Castle"]["extractedText"] == "Bouncy Castle"
    assert _spdx_license(None, extracted) == "NOASSERTION"


@pytest.mark.parametrize("expression, any_id, valid", [
    ("Apache-2.0", False, True),
    ("(MIT OR Apache-2.0) AND BSD-3-Clause", False, True),
    ("MIT or Apache-2.0", False, False),
    ("MIT OR", False, False),
    ("(MIT", False, False),
    ("Not-A-License", False, False),
    ("Not-A-License", True, True),
    ("GPL-2.0-only WITH Classpath-exception-2.0", False, False),
    ("GPL-2.0-only WITH Classpath-exception-2.0", True, True),
    ("LicenseRef-vendor", True, False),
])
def test_spdx_expressions_are_checked_before_they_are_passed_on(expression, any_id, valid):
    assert is_spdx_expression(expression, any_id=any_id) is valid
