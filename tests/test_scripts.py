"""Copied JavaScript files: which are looked up, and when a hash-index hit names a version."""
import base64
import hashlib
import json

from binwitness.net import Net
from binwitness.output import render_summary
from binwitness.scan import Options, scan

from helpers import ScriptedTransport

# Minified: one long line, the way published dist files look.
POLYFILL = ("!function(){" + "var a=1;" * 200 + "}();").encode()
JQUERY = ("/*! jQuery v3.6.0 | (c) OpenJS Foundation */\n!function(e){" + "e.x=1;" * 200 + "}();").encode()
OLDER_JQUERY = JQUERY.replace(b"e.x=1", b"e.y=1")
NEWER_JQUERY = JQUERY.replace(b"e.x=1", b"e.z=1")
BUNDLE = ("(self.webpackChunkapp=self.webpackChunkapp||[]).push([[1],{" + "1:function(){}," * 100 + "}]);").encode()
MINIFIED_UNKNOWN = ("!function(){" + "var b=2;" * 200 + "}();").encode()
OWN_SOURCE = "".join(f"export function step{i}(value) {{\n  return value + {i};\n}}\n" for i in range(40)).encode()
WEBPACK_CONFIG = ("/*! build */\nmodule.exports = {\n" + "".join(f"  key{i}: {i},\n" for i in range(120))
                  + "};\n").encode()
VENDORED_OWN = OWN_SOURCE + b"\n// copy"


def b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def release(*files: bytes) -> dict:
    return {"files": [{"name": f"/dist/file{i}.js", "hash": b64(data)} for i, data in enumerate(files)]}


def hash_hit(data: bytes, name: str, version: str) -> tuple[str, dict]:
    return f"/lookup/hash/{hashlib.sha256(data).hexdigest()}", {"type": "npm", "name": name, "version": version,
                                                                 "file": "/dist/file0.js"}


def versions(*listed: str) -> dict:
    return {"versions": {v: {} for v in listed}}


ROUTES = dict([
    hash_hit(POLYFILL, "next", "15.0.2"),
    hash_hit(JQUERY, "jquery", "3.6.0"),
    ("/lookup/hash/", None),
    # The polyfill is the same file in three releases in a row; jQuery's file is its release's own.
    ("/packages/npm/next@15.0.1?", release(POLYFILL)),
    ("/packages/npm/next@15.0.2?", release(POLYFILL)),
    ("/packages/npm/next@15.0.3?", release(POLYFILL)),
    ("/packages/npm/next@15.3.0?", release(POLYFILL)),
    ("/packages/npm/next@14.2.0?", release(b"other")),
    ("/packages/npm/jquery@3.5.1?", release(OLDER_JQUERY)),
    ("/packages/npm/jquery@3.6.0?", release(JQUERY)),
    ("/packages/npm/jquery@3.6.1?", release(NEWER_JQUERY)),
    ("registry.npmjs.org/next", versions("14.2.0", "15.0.1", "15.0.2", "15.0.3", "15.3.0", "15.4.0-canary.1")),
    ("registry.npmjs.org/jquery", versions("3.5.1", "3.6.0", "3.6.1", "3.6.1-rc.1")),
])


def scan_tree(tmp_path, files: dict[str, bytes], routes=None):
    for name, data in files.items():
        target = tmp_path / "app" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    transport = ScriptedTransport(routes or ROUTES)
    net = Net(cache_dir=tmp_path / "cache", transport=transport, sleep=lambda s: None)
    result = scan([tmp_path / "app"], net, Options(licenses=False, vulnerabilities=False), log=lambda m: None)
    return result, transport


def named(result):
    return {(c["name"], c["version"]) for c in result["components"]}


def test_a_file_that_several_releases_in_a_row_hold_gets_no_version(tmp_path):
    result, _ = scan_tree(tmp_path, {"static/js/polyfill.js": POLYFILL})
    assert named(result) == set()
    assert result["scripts_without_version"] == [{
        "package": "next", "file": "/dist/file0.js", "same_file_in": ["15.0.1", "15.0.2", "15.0.3"],
        "reason": "releases next to each other hold this exact file", "locations": ["app/static/js/polyfill.js"]}]
    assert result["summary"]["scripts"]["version_not_determined"] == 1
    assert "scripts      version not determined 1" in render_summary(result)


def test_a_file_only_its_own_release_holds_is_pinned_to_it(tmp_path):
    result, _ = scan_tree(tmp_path, {"static/js/jquery.min.js": JQUERY})
    assert named(result) == {("jquery", "3.6.0")}
    [component] = result["components"]
    assert component["confidence"] == "exact"
    assert "neighbouring releases hold a different file" in component["evidence"][0]["method"]


def test_the_version_a_lockfile_declares_takes_the_file(tmp_path):
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"},
                                                          "node_modules/next": {"version": "15.3.0"}}}).encode()
    result, _ = scan_tree(tmp_path, {"package-lock.json": lock, "static/js/polyfill.js": POLYFILL})
    assert named(result) == {("next", "15.3.0")}
    [component] = result["components"]
    assert sorted(component["locations"]) == ["app/package-lock.json", "app/static/js/polyfill.js"]
    assert result["scripts_without_version"] == []


def test_project_sources_and_build_configs_are_not_looked_up(tmp_path):
    # Anywhere else, and under a source directory with a library's marks, a file is looked up.
    umd = b"(function (global, factory) {\n" + OWN_SOURCE
    result, transport = scan_tree(tmp_path, {"src/main.js": OWN_SOURCE, "webpack.config.js": WEBPACK_CONFIG,
                                             "src/lib/copied.js": VENDORED_OWN, "web/plain.js": OWN_SOURCE + b"//",
                                             "src/umd.js": umd})
    looked_up = {url.rsplit("/", 1)[1] for _, url, _ in transport.calls if "/lookup/hash/" in url}
    assert looked_up == {hashlib.sha256(data).hexdigest() for data in (VENDORED_OWN, OWN_SOURCE + b"//", umd)}
    assert result["project_scripts"] == ["app/src/main.js", "app/webpack.config.js"]
    assert result["summary"]["scripts"]["project_files_not_looked_up"] == 2


def test_bundler_output_is_told_apart_from_an_unknown_library(tmp_path):
    result, _ = scan_tree(tmp_path, {"static/js/app.js": BUNDLE, "static/js/chart.min.js": MINIFIED_UNKNOWN,
                                     "static/js/main.3f2a1b9c.js": MINIFIED_UNKNOWN + b";"})
    assert result["bundled_scripts"] == ["app/static/js/app.js", "app/static/js/main.3f2a1b9c.js"]
    assert result["unmatched_scripts"] == ["app/static/js/chart.min.js"]
    assert "scripts      bundles 2, unmatched 1" in render_summary(result)
