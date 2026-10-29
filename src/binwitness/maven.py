"""Maven coordinates from registries: hash lookups, published-artifact comparison and POM licenses.

A coordinate is only ever taken from a registry hash match or from the jar's own pom.properties. File names
are never turned into coordinates: jars built by Gradle carry no pom.properties, and a guessed groupId
attaches the wrong project's advisories.
"""
from __future__ import annotations

import base64
import posixpath
import re
import struct
import urllib.parse
from collections import Counter

from binwitness.jar import split_name
from binwitness.licenses import detect, pom_licenses
from binwitness.net import Net, NetError

DEPS_DEV = "https://api.deps.dev/v3"
CENTRAL = "https://repo1.maven.org/maven2"
CENTRAL_SEARCH = "https://search.maven.org/solrsearch/select"
# The end of a jar holds its central directory: the name, CRC-32 and size of every entry. 64 KiB covers the
# directory of a jar with several hundred entries in one request; larger ones take a second.
TAIL = 64 * 1024
LIST_LIMIT = 20
# io.netty has about 130 artifacts; a group larger than this is not one project.
GROUP_LIMIT = 200
# Rewritten whenever a jar is re-zipped, without changing any code it ships: the manifest (attributes
# reordered, version headers dropped), the jar index, and signatures, which re-zipping invalidates. Maven's
# build metadata (pom.xml, pom.properties) is in the same position: release builds rewrite the pom (Nacos
# flattens it), and vendors strip it from the jars they rename.
PACKAGING = re.compile(r"META-INF/(MANIFEST\.MF|INDEX\.LIST|[^/]+\.(SF|RSA|DSA|EC)|maven/.+)$", re.I)
PACKAGING_TEXT = "the manifest, index, signatures and Maven build metadata"


def lookup_hash(net: Net, sha1: str, filename: str, db=None, declared: tuple[str, str, str] | None = None) -> dict | None:
    """Registry entry whose published file has exactly this SHA-1, or None. ``declared`` is the coordinate in
    the jar's own pom.properties: of several coordinates publishing the same file, it names the original."""
    stem = split_name(filename)[0]

    def named(candidate) -> bool:
        return stem == f"{candidate[1]}-{candidate[2]}" or stem.startswith(f"{candidate[1]}-{candidate[2]}-")

    candidates, source = [], "Maven Central index, local copy"
    if db is not None and db.has("maven-hashes"):
        candidates = [(*c, None) for c in db.coordinates_for_sha1(sha1)]
    # The local index files each jar under a single coordinate, so a file that another project republished
    # (commons-io inside NetBeans) can sit under the republisher's name, and it lacks some artifacts. Unless
    # it names the file as the file names itself, the registry's full list decides, as without the index.
    settled = any(named(c) for c in candidates) and (declared is None or declared in {c[:3] for c in candidates})
    if not settled:
        try:
            listed = _deps_dev(net, sha1)
        except NetError:
            if not candidates:
                raise
            listed = []
        if listed:
            candidates = listed + [c for c in candidates if c[:3] not in {x[:3] for x in listed}]
            source = "deps.dev"
    if not candidates:
        query = urllib.parse.quote(f'1:"{sha1}"')
        docs = (net.get_json(f"{CENTRAL_SEARCH}?q={query}&rows=20&wt=json", stable=True) or {}).get(
            "response", {}).get("docs", [])
        candidates = [(d["g"], d["a"], d["v"], None) for d in docs if d.get("g") and d.get("a") and d.get("v")]
        source = "search.maven.org"
    if not candidates:
        return None
    # The same file can be published under several coordinates (a project that moved its groupId).
    pick = next((c for c in candidates if c[:3] == declared), None) or next((c for c in candidates if named(c)),
                                                                             candidates[0])
    return {"coordinate": pick[:3], "source": source, "licenses": pick[3],
            "alternatives": [c[:3] for c in candidates if c[:3] != pick[:3]]}


def _deps_dev(net: Net, sha1: str) -> list[tuple]:
    value = urllib.parse.quote(base64.b64encode(bytes.fromhex(sha1)).decode(), safe="")
    found = net.get_json(f"{DEPS_DEV}/query?hash.type=SHA1&hash.value={value}", stable=True) or {}
    hits = [r["version"] for r in found.get("results", []) if r["version"]["versionKey"]["system"] == "MAVEN"]
    return [(*h["versionKey"]["name"].split(":", 1), h["versionKey"]["version"], h.get("licenses", [])) for h in hits]


def _published_url(coordinate: tuple[str, str, str], filename: str, repository: str = CENTRAL) -> str:
    group, artifact, version = coordinate
    stem, extension = split_name(filename)
    classifier = stem[len(f"{artifact}-{version}-"):] if stem.startswith(f"{artifact}-{version}-") else ""
    name = f"{artifact}-{version}-{classifier}{extension}" if classifier else f"{artifact}-{version}{extension}"
    return f"{repository}/{group.replace('.', '/')}/{artifact}/{version}/{name}"


def published_status(net: Net, coordinate: tuple[str, str, str], filename: str, sha1: str,
                     repositories: tuple[str, ...] = ()) -> tuple[str, str | None]:
    """Compare a jar that no registry recognised with the file published under its declared coordinate:
    (status, the repository that publishes it). ``repositories`` are consulted after Maven Central.

    Only the checksum a repository serves next to the file decides. The local hash index cannot: it keeps
    one coordinate per file, mixes classifier jars in with the main one, and has stale entries
    (javassist 3.18.1-GA), and a wrong "differs" accuses a jar of having been rebuilt.
    """
    if coordinate[2].upper().endswith("SNAPSHOT"):
        return "snapshot", None
    differing = None
    for repository in (CENTRAL, *repositories):
        text = net.get(f"{_published_url(coordinate, filename, repository)}.sha1", stable=True)
        if text is None:
            continue
        published = text.decode("ascii", "replace").split()
        if published and published[0].lower() == sha1:
            return "identical", repository
        differing = differing or repository
    return ("differs", differing) if differing else ("not-on-central", None)


def compare_with_published(net: Net, coordinate: tuple[str, str, str], filename: str,
                           local: dict[str, tuple[int, int]], repository: str = CENTRAL) -> dict | None:
    """Entry-by-entry comparison with the published jar, read from its central directory alone.

    None when the published jar's directory cannot be read (absent, zip64, malformed).
    """
    url = _published_url(coordinate, filename, repository)
    tail = net.get(url, stable=True, headers={"Range": f"bytes=-{TAIL}"})
    if tail is None:
        return None
    published = _central_directory(net, url, tail)
    if published is None:
        return None
    differences = {"changed": sorted(n for n in local.keys() & published.keys() if local[n] != published[n]),
                   "added": sorted(local.keys() - published.keys()),
                   "removed": sorted(published.keys() - local.keys())}
    packaging = sorted(n for names in differences.values() for n in names if PACKAGING.match(n))
    content = {kind: [n for n in names if not PACKAGING.match(n)] for kind, names in differences.items()}
    unchanged = sum(1 for n, v in published.items() if local.get(n) == v and not PACKAGING.match(n))
    return {"published_entries": len(published), "unchanged": unchanged, "packaging_only": packaging,
            "counts": {kind: len(names) for kind, names in content.items()},
            "relocated": _relocation(content["removed"], content["added"]),
            **{kind: names[:LIST_LIMIT] for kind, names in content.items()}}


def _relocation(removed: list[str], added: list[str]) -> dict | None:
    """The package rename that carries the most removed entries onto added ones (``org/postgresql`` ->
    ``cn/vendor``), with the number of entries it carries. Relocating rewrites class files, so their CRCs
    cannot be compared; the names still line up."""
    by_name: dict[str, list[str]] = {}
    for name in added:
        by_name.setdefault(posixpath.basename(name), []).append(name)
    renames = Counter()
    for name in removed:
        for other in by_name.get(posixpath.basename(name), [])[:20]:
            left, right = name.split("/"), other.split("/")
            shared = next(i for i in range(1, min(len(left), len(right)) + 1)
                          if i == min(len(left), len(right)) or left[-i - 1] != right[-i - 1])
            if len(left) > shared and len(right) > shared:
                renames["/".join(left[:-shared]), "/".join(right[:-shared])] += 1
    if not renames:
        return None
    (source, target), _ = renames.most_common(1)[0]
    present = set(added)
    carried = sum(1 for n in removed if n.startswith(source + "/") and f"{target}/{n[len(source) + 1:]}" in present)
    return {"from": source, "to": target, "entries": carried}


def find_by_class(net: Net, class_name: str, versions: list[str]) -> list[tuple[str, str, str]]:
    """Artifacts on Maven Central that contain this class, at one of these versions.

    Candidates only: a jar that shades the class is listed as well, so each must still pass a content check.
    """
    alternatives = " OR ".join(f'"{v}"' for v in versions)
    query = urllib.parse.quote(f"fc:{class_name} AND v:({alternatives})")
    docs = (net.get_json(f"{CENTRAL_SEARCH}?q={query}&rows=20&wt=json", stable=True) or {}).get(
        "response", {}).get("docs", [])
    found = [(d["g"], d["a"], d["v"]) for d in docs if d.get("g") and d.get("a") and d.get("v")]
    # The project that owns the package is the likeliest; jars that shade it come after.
    return sorted(found, key=lambda c: not class_name.startswith(c[0] + "."))


def group_artifacts(net: Net, group: str) -> list[str]:
    """The artifactIds Maven Central lists under a groupId (one search result per artifact)."""
    query = urllib.parse.quote(f'g:"{group}"')
    docs = (net.get_json(f"{CENTRAL_SEARCH}?q={query}&rows={GROUP_LIMIT}&wt=json", stable=True) or {}).get(
        "response", {}).get("docs", [])
    return sorted({d["a"] for d in docs if d.get("g") == group and d.get("a")})


def find_artifacts_by_class(net: Net, class_name: str) -> list[tuple[str, str]]:
    """Artifacts on Maven Central that contain this class in any release, as (groupId, artifactId).

    For releases published elsewhere only (milestones on a vendor's repository): Central's index still knows
    the artifact from its other releases."""
    query = urllib.parse.quote(f"fc:{class_name}")
    docs = (net.get_json(f"{CENTRAL_SEARCH}?q={query}&rows={LIST_LIMIT}&wt=json", stable=True) or {}).get(
        "response", {}).get("docs", [])
    found = list(dict.fromkeys((d["g"], d["a"]) for d in docs if d.get("g") and d.get("a")))
    return sorted(found, key=lambda c: not class_name.startswith(c[0] + "."))


def _central_directory(net: Net, url: str, tail: bytes) -> dict[str, tuple[int, int]] | None:
    """name -> (CRC-32, size) of the file entries, from the end of a zip (or the whole of it)."""
    at = len(tail)
    while True:
        at = tail.rfind(b"PK\x05\x06", 0, at)
        if at < 0 or len(tail) - at < 22:
            return None
        count, size, offset, comment = struct.unpack("<10xHIIH", tail[at:at + 22])
        if at + 22 + comment == len(tail):
            break
    if count == 0xFFFF or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        return None
    if at >= size:
        directory = tail[at - size:at]
    else:
        directory = net.get(url, stable=True, headers={"Range": f"bytes={offset}-{offset + size - 1}"})
        if directory is not None and len(directory) > size:  # the server ignored the range
            directory = directory[offset:offset + size]
        if directory is None or len(directory) != size:
            return None
    out, position = {}, 0
    for _ in range(count):
        if directory[position:position + 4] != b"PK\x01\x02" or len(directory) < position + 46:
            return None
        flags, crc, file_size, name_length, extra_length, comment_length = struct.unpack(
            "<8xH6xI4xIHHH12x", directory[position:position + 46])
        raw = directory[position + 46:position + 46 + name_length]
        name = raw.decode("utf-8" if flags & 0x800 else "cp437", "replace")
        if not name.endswith("/"):
            out[name] = (crc, file_size)
        position += 46 + name_length + extra_length + comment_length
    return out


def registry_licenses(net: Net, coordinate: tuple[str, str, str]) -> list[str]:
    group, artifact, version = coordinate
    quote = urllib.parse.quote
    found = net.get_json(f"{DEPS_DEV}/systems/maven/packages/{quote(f'{group}:{artifact}', safe='')}"
                         f"/versions/{quote(version, safe='')}", stable=True) or {}
    return [e for e in found.get("licenses", []) if e and e.lower() != "non-standard"]


def central_licenses(net: Net, group: str, artifact: str, version: str, depth: int = 0,
                     repositories: tuple[str, ...] = ()) -> list[str]:
    """``<licenses>`` of the published POM, following ``<parent>`` the way Maven inherits it (4 levels).
    ``repositories`` are consulted after Maven Central."""
    pom = None
    for repository in (CENTRAL, *repositories):
        pom = net.get(f"{repository}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom",
                      stable=True)
        if pom:
            break
    if not pom:
        return []
    text = pom.decode("utf-8", "replace")
    names = pom_licenses(text)
    parent = re.search(r"<parent>(.*?)</parent>", re.sub(r"<!--.*?-->", "", text, flags=re.S), re.S)
    if names or not parent or depth >= 4:
        return names
    ref = {k: re.search(rf"<{k}>\s*([^<]+?)\s*</{k}>", parent.group(1)) for k in ("groupId", "artifactId", "version")}
    if not all(ref.values()):
        return []
    return central_licenses(net, *(ref[k].group(1) for k in ("groupId", "artifactId", "version")), depth + 1,
                            repositories)


def licenses_for(net: Net, coordinate: tuple[str, str, str], hinted: list[str] | None,
                 repositories: tuple[str, ...] = ()) -> dict | None:
    """License declaration from the registry; ``hinted`` are expressions a hash lookup already returned."""
    expressions = [e for e in (hinted or []) if e and e.lower() != "non-standard"] or registry_licenses(
        net, coordinate)
    if expressions and any(detect(e) for e in expressions):
        return {"expressions": expressions, "source": "deps.dev"}
    names = central_licenses(net, *coordinate)
    if names:
        return {"names": names, "source": "Maven Central POM"}
    for repository in repositories:
        names = central_licenses(net, *coordinate, repositories=(repository,))
        if names:
            return {"names": names, "source": f"POM from {repository}"}
    return None
