import json

import pytest

from binwitness.jar import jar_facts
from binwitness.licenses import detect, expression_family, family
from binwitness.npm import parse
from binwitness.versions import compare, in_range
from binwitness.vulns import cvss3_score

from helpers import make_jar


def test_jar_picks_its_own_coordinates_and_lists_shaded_ones():
    data = make_jar("org.example", "app", "2.0", {
        "META-INF/maven/org.other/inner/pom.properties": "groupId=org.other\nartifactId=inner\nversion=1.1\n",
        "META-INF/maven/org.example/app/pom.xml":
            "<project><licenses><license><name>The Apache License, Version 2.0</name></license></licenses></project>",
    })
    facts = jar_facts("app-2.0.jar", data)
    assert facts.coordinate == ("org.example", "app", "2.0")
    assert facts.embedded == [("org.other", "inner", "1.1")]
    assert facts.licenses == ["Apache-2.0"] and facts.license_source == "jar: pom.xml"


def test_all_in_one_netty_lists_modules_but_a_module_jar_does_not():
    listing = "\n".join(f"{m}.version=4.1.54.Final\n{m}.buildDate=2020" for m in
                        ("netty-common", "netty-codec-http", "netty-all"))
    merged = jar_facts("netty-all-4.1.54.Final.jar", make_jar("io.netty", "netty-all", "4.1.54.Final", {
        "META-INF/io.netty.versions.properties": listing}))
    assert merged.merged == [("io.netty", "netty-codec-http", "4.1.54.Final"),
                             ("io.netty", "netty-common", "4.1.54.Final")]
    single = jar_facts("netty-common-4.1.54.Final.jar", make_jar("io.netty", "netty-common", "4.1.54.Final", {
        "META-INF/io.netty.versions.properties": "netty-common.version=4.1.54.Final\n"}))
    assert single.merged == []


def test_a_corrupt_entry_is_reported_and_the_rest_of_the_jar_still_read():
    data = bytearray(make_jar("org.example", "app", "2.0"))
    data[:4] = b"XXXX"      # local header of the first entry, the manifest; the central directory is intact
    facts = jar_facts("app-2.0.jar", bytes(data))
    assert facts.coordinate == ("org.example", "app", "2.0")
    assert len(facts.damaged) == 1 and facts.damaged[0].startswith("META-INF/MANIFEST.MF: ")


def test_gpl_version_is_read_next_to_the_gpl_title():
    text = ("Licensing Information User Manual\nThis product is licensed under the GNU General Public License, "
            "version 2, with the Universal FOSS Exception, version 1.0.\n" + "x " * 400
            + "Third-party notice: GNU GPL version 3 applies to something else.")
    assert detect(text, first_only=True) == ["GPL-2.0-with-FOSS-exception"]


def test_classpath_exception_at_the_end_of_a_long_text():
    text = "GNU General Public License version 2\n" + "terms " * 5000 + "CLASSPATH EXCEPTION"
    assert detect(text, first_only=True) == ["GPL-2.0-with-classpath-exception"]


@pytest.mark.parametrize("expression, expected", [
    ("Apache-2.0", "permissive"),
    ("EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0", "weak-copyleft"),
    ("MIT AND GPL-3.0-only", "strong-copyleft"),
    ("(MIT OR GPL-3.0-only) AND LGPL-2.1-only", "weak-copyleft"),
    ("GPL-2.0-only WITH Classpath-exception-2.0", "copyleft-with-exception"),
    ("AGPL-3.0-only", "strong-copyleft"),
    ("LicenseRef-Proprietary", "unknown"),
    ("MIT AND LicenseRef-Proprietary", "unknown"),
])
def test_spdx_expression_family(expression, expected):
    assert expression_family(expression) == expected


def test_listed_names_are_alternatives_unless_conjunctive():
    assert family(["LGPL", "Apache-2.0"]) == "permissive"
    assert family(["LGPL", "Apache-2.0"], conjunctive=True) == "weak-copyleft"


def test_package_lock_v3_marks_dev_dependencies():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/lodash": {"version": "4.17.20", "license": "MIT"},
        "node_modules/jest": {"version": "29.0.0", "dev": True},
        "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
        "node_modules/linked": {"link": True},
    }}
    packages = parse("package-lock.json", json.dumps(lock).encode())
    assert [(p.name, p.version, p.scope, p.license) for p in packages] == [
        ("lodash", "4.17.20", "runtime", "MIT"), ("jest", "29.0.0", "dev", None),
        ("@scope/b", "1.0.0", "runtime", None)]


def test_package_lock_v1_nested():
    lock = {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": True}}},
        "git-dep": {"version": "github:user/repo#abc"}}}
    packages = parse("package-lock.json", json.dumps(lock).encode())
    assert [(p.name, p.version, p.scope) for p in packages] == [("a", "1.0.0", "runtime"), ("b", "2.0.0", "dev")]


def test_yarn_classic_and_berry():
    classic = b'''# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.12.3"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.12.3.tgz"

lodash@^4.17.0:
  version "4.17.21"
'''
    berry = b'''__metadata:
  version: 6

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"app@workspace:.":
  version: 0.0.0-use.local
'''
    assert [(p.name, p.version) for p in parse("yarn.lock", classic)] == [("@babel/core", "7.12.3"),
                                                                        ("lodash", "4.17.21")]
    assert [(p.name, p.version) for p in parse("yarn.lock", berry)] == [("lodash", "4.17.21")]


def test_pnpm_lock_versions_5_6_and_9():
    v5 = b"lockfileVersion: 5.4\npackages:\n  /lodash/4.17.21:\n    dev: false\n  /@types/node/18.0.0_abc:\n    dev: true\n"
    v6 = b"lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.21:\n    dev: false\n  /react-dom@18.2.0(react@18.2.0):\n    dev: true\n"
    v9 = b"lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n  '@types/node@18.0.0':\n    resolution: {}\nsnapshots:\n  lodash@4.17.21: {}\n"
    assert [(p.name, p.version, p.scope) for p in parse("pnpm-lock.yaml", v5)] == [
        ("lodash", "4.17.21", "runtime"), ("@types/node", "18.0.0", "dev")]
    assert [(p.name, p.version, p.scope) for p in parse("pnpm-lock.yaml", v6)] == [
        ("lodash", "4.17.21", "runtime"), ("react-dom", "18.2.0", "dev")]
    assert [(p.name, p.version, p.scope) for p in parse("pnpm-lock.yaml", v9)] == [
        ("lodash", "4.17.21", "unknown"), ("@types/node", "18.0.0", "unknown")]


def test_installed_package_json():
    data = json.dumps({"name": "left-pad", "version": "1.3.0", "licenses": [{"type": "WTFPL"}]}).encode()
    assert [(p.name, p.license) for p in parse("node_modules/left-pad/package.json", data)] == [("left-pad", "WTFPL")]


@pytest.mark.parametrize("ecosystem, left, right, expected", [
    ("maven", "4.1.54.Final", "4.1.77.Final", -1),
    ("maven", "2.9.10.1", "2.9.10", 1),
    ("maven", "1.0", "1.0.0", 0),
    ("maven", "1.0-rc1", "1.0", -1),
    ("maven", "1.0-SNAPSHOT", "1.0", -1),
    ("maven", "5.2.8.RELEASE", "5.2.9", -1),
    ("maven", "3.27.0-GA", "3.27.0", 0),
    ("npm", "1.2.3-beta.1", "1.2.3", -1),
    ("npm", "10.0.0", "9.9.9", 1),
])
def test_version_order(ecosystem, left, right, expected):
    assert compare(ecosystem, left, right) == expected


def test_github_ranges():
    assert in_range("maven", "4.1.54.Final", "< 4.1.77.Final") is True
    assert in_range("maven", "2.9.10.1", ">= 2.0.0, < 2.9.10.1") is False
    assert in_range("npm", "4.17.20", ">= 4.0.0, <= 4.17.20") is True
    assert in_range("npm", "1.0.0", "= 1.0.0") is True


@pytest.mark.parametrize("vector, score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_base_score(vector, score):
    assert cvss3_score(vector) == score
