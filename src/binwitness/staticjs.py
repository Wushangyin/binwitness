"""Vendored JavaScript files (``static/js/jquery.min.js``) matched to npm releases.

The jsDelivr hash index answers with whichever copy it saw first, often some GitHub repository that
vendors the library, so a hit only counts when the file is byte-identical to a file of an npm release.
It also names one release when many hold the same file (a polyfill unchanged across a dozen releases),
so a hit is only pinned to a version once the releases next to it hold a different file.
"""
from __future__ import annotations

import base64
import functools
import posixpath
import re
import urllib.parse

from binwitness.net import Net
from binwitness.upgrades import NPM_ABBREVIATED, NPM_REGISTRY
from binwitness.versions import compare, prerelease

JSDELIVR = "https://data.jsdelivr.com/v1"
HEAD_SIZE = 4096
# Build and tool configuration: always the project's own.
CONFIG_FILE = re.compile(r"(?:^|[.-])(?:config|conf)\.[cm]?js$|^\.[\w.-]+rc\.[cm]?js$|^(?:gulpfile|gruntfile)\.[cm]?js$",
                         re.I)
# Where projects keep their own sources, and where copied libraries and web assets go. A file under both
# (src/main/webapp/js/) counts as an asset.
SOURCE_DIRS = {"src", "source", "sources", "scripts", "test", "tests", "__tests__", "spec", "specs", "e2e", "mock",
               "mocks", "__mocks__"}
ASSET_DIRS = {"vendor", "vendors", "lib", "libs", "plugin", "plugins", "third-party", "thirdparty", "third_party",
              "3rdparty", "bower_components", "webjars", "external", "externals", "static", "assets", "public",
              "webapp", "webroot", "wwwroot", "resources", "js", "javascript", "javascripts", "dist"}
# What published files carry and a project's own sources rarely do: a license notice, a UMD or CommonJS
# wrapper left by a library build, or minification.
LIBRARY_SIGNS = re.compile(rb"/\*!|//!|@license|@preserve|copyright|\(c\)\s*(?:19|20)\d\d|licen[cs]ed (?:under|to)|"
                           rb"released under|public domain|typeof exports\s*===?\s*['\"]object|"
                           rb"typeof define\s*===?\s*['\"]function|define\.amd|__esModule|"
                           rb"\(function\s*\(\s*(?:global|root)\s*,\s*factory", re.I)
MINIFIED_LINE = 500
BUNDLER = re.compile(rb"webpackJsonp|webpackChunk|__webpack_require__|__vite|System\.register\(|parcelRequire|"
                     rb"TURBOPACK")
CONTENT_HASH = re.compile(r"[.-]([A-Za-z0-9_]{8,})(?:\.min)?\.[cm]?js$")
# "/*! jQuery v3.6.0 | ..." or "/** @license React v16.14.0" style banners.
BANNER = re.compile(r"/\*[*!]\s*(?:@license\s+)?([A-Za-z@][\w.@/-]{0,60}?)\s+v?(\d+\.\d+\.\d+[\w.+-]*)")


def worth_looking_up(locations: list[str], head: bytes) -> bool:
    """False for the project's own files, which no registry holds: build configuration, and plain sources
    under a source directory (src/, scripts/, tests/) outside any asset or library directory. Everything
    else is looked up, so a copied library is not missed for want of a banner."""
    names = [posixpath.basename(location.rsplit("!/", 1)[-1]) for location in locations]
    if all(CONFIG_FILE.search(name) for name in names):
        return False
    for location in locations:
        parts = {part.lower() for part in location.replace("!/", "/").split("/")[:-1]}
        if parts & ASSET_DIRS or not parts & SOURCE_DIRS:
            return True
    return bool(LIBRARY_SIGNS.search(head)) or any(len(line) >= MINIFIED_LINE for line in head.split(b"\n"))


def is_bundle(locations: list[str], head: bytes) -> bool:
    """Bundler output (webpack, Vite, Parcel chunks): the project's code compiled together with libraries,
    so no published file matches it."""
    if BUNDLER.search(head):
        return True
    for location in locations:
        found = CONTENT_HASH.search(posixpath.basename(location))
        if found and re.search(r"\d", found.group(1)) and re.search(r"[A-Za-z]", found.group(1)):
            return True
    return False


def identify(net: Net, digest: bytes, head: bytes, declared: dict | None = None) -> dict | None:
    """``digest`` is the file's SHA-256, ``head`` its first bytes (where banners live), ``declared`` the npm
    versions that lockfiles or package.json files in the same scan name, by package."""
    hit = net.get_json(f"{JSDELIVR}/lookup/hash/{digest.hex()}", stable=True)
    candidates = []
    if hit and hit.get("type") == "npm":
        return pin(net, hit, base64.b64encode(digest).decode(), (declared or {}).get(hit["name"], ()))
    if hit and hit.get("type") == "gh" and re.match(r"v?\d", hit.get("version") or ""):
        candidates.append((hit["name"].rsplit("/", 1)[-1].lower(), hit["version"].lstrip("v")))
    candidates += banners(head)
    for name, version in dict.fromkeys(candidates):
        file = file_in_release(net, name, version, base64.b64encode(digest).decode())
        if file:
            return {"name": name, "version": version, "file": file,
                    "method": "byte-identical to a file of the npm release (jsDelivr)", "confidence": "exact"}
    for name, version in banners(head)[:1]:
        if release_exists(net, name, version):
            return {"name": name, "version": version, "file": "",
                    "method": "banner comment names an npm release; file differs from the release",
                    "confidence": "declared"}
    return None


def pin(net: Net, hit: dict, sha256_b64: str, declared) -> dict:
    """A version for a file-hash hit. Returns either name/version or, when releases next to the hit hold the
    same file, ``version`` None with ``same_file_in``."""
    name, version, file = hit["name"], hit["version"], hit.get("file", "")
    own = [v for v in sorted(declared, key=_npm_order) if file_in_release(net, name, v, sha256_b64)]
    if own:
        return {"name": name, "versions": own, "file": file, "confidence": "exact",
                "method": "jsDelivr file-hash index; the version is the one a lockfile or package.json declares"}
    releases = release_versions(net, name)
    if version not in releases:
        return {"name": name, "version": None, "file": file, "same_file_in": [version],
                "reason": "the npm registry does not list the release the hash index names"}
    pool = [v for v in releases if v == version or prerelease("npm", version) or not prerelease("npm", v)]
    index = pool.index(version)
    same = [v for v in pool[max(index - 1, 0):index + 2]
            if v == version or file_in_release(net, name, v, sha256_b64)]
    if len(same) > 1:
        return {"name": name, "version": None, "file": file, "same_file_in": same,
                "reason": "releases next to each other hold this exact file"}
    return {"name": name, "version": version, "file": file, "confidence": "exact",
            "method": "jsDelivr file-hash index; the neighbouring releases hold a different file"}


def release_versions(net: Net, name: str) -> list[str]:
    """Published versions in version order (the registry's abbreviated document, shared with upgrade advice)."""
    document = net.get_json(f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}",
                            headers={"Accept": NPM_ABBREVIATED})
    return sorted((document or {}).get("versions") or {}, key=_npm_order)


_npm_order = functools.cmp_to_key(lambda a, b: compare("npm", a, b))


def banners(head: bytes) -> list[tuple[str, str]]:
    out = []
    for name, version in BANNER.findall(head[:HEAD_SIZE].decode("utf-8", "replace")):
        name = name.lower()
        name = re.sub(r"\.js$", "", name)
        out.append((name, version))
    return out


def _release_files(net: Net, name: str, version: str) -> dict | None:
    quote = urllib.parse.quote
    return net.get_json(f"{JSDELIVR}/packages/npm/{quote(name, safe='@/')}@{quote(version, safe='')}?structure=flat",
                        stable=True)


def file_in_release(net: Net, name: str, version: str, sha256_b64: str) -> str | None:
    listing = _release_files(net, name, version)
    for entry in (listing or {}).get("files", []):
        if entry.get("hash") == sha256_b64:
            return entry["name"]
    return None


def release_exists(net: Net, name: str, version: str) -> bool:
    return bool(_release_files(net, name, version))
