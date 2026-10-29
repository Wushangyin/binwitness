"""Vendored JavaScript files (``static/js/jquery.min.js``) matched to npm releases.

The jsDelivr hash index answers with whichever copy it saw first, often some GitHub repository that
vendors the library, so a hit only counts when the file is byte-identical to a file of an npm release.
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from binwitness.net import Net

JSDELIVR = "https://data.jsdelivr.com/v1"
HEAD_SIZE = 4096
# "/*! jQuery v3.6.0 | ..." or "/** @license React v16.14.0" style banners.
BANNER = re.compile(r"/\*[*!]\s*(?:@license\s+)?([A-Za-z@][\w.@/-]{0,60}?)\s+v?(\d+\.\d+\.\d+[\w.+-]*)")


def identify(net: Net, digest: bytes, head: bytes) -> dict | None:
    """``digest`` is the file's SHA-256, ``head`` its first bytes (where banners live)."""
    hit = net.get_json(f"{JSDELIVR}/lookup/hash/{digest.hex()}", stable=True)
    candidates = []
    if hit and hit.get("type") == "npm":
        return {"name": hit["name"], "version": hit["version"], "file": hit.get("file", ""),
                "method": "jsDelivr file-hash index", "confidence": "exact"}
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
