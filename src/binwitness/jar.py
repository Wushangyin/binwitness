"""Facts a jar states about itself: Maven coordinates, embedded components, manifest and license texts."""
from __future__ import annotations

import hashlib
import io
import posixpath
import re
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from binwitness.archive import listed_once
from binwitness.licenses import detect, manifest_value, pom_licenses

MANIFEST_KEYS = ("Implementation-Title", "Implementation-Version", "Implementation-Vendor",
                 "Bundle-SymbolicName", "Bundle-Version", "Automatic-Module-Name")
NETTY_VERSIONS = "META-INF/io.netty.versions.properties"
# Extensions a Maven artifact that is a zip of classes is published with.
ARTIFACT_EXTENSION = re.compile(r"\.(jar|hpi|jpi|aar|nar|kar|rar)$", re.I)


@dataclass
class JarFacts:
    filename: str
    sha1: str
    sha256: str
    size: int
    coordinate: tuple[str, str, str] | None = None    # from the jar's own pom.properties
    embedded: list[tuple[str, str, str]] = field(default_factory=list)  # other pom.properties (shaded in)
    merged: list[tuple[str, str, str]] = field(default_factory=list)    # modules of an all-in-one artifact
    manifest: dict[str, str] = field(default_factory=dict)
    licenses: list[str] = field(default_factory=list)
    license_source: str = ""
    readable: bool = True
    damaged: list[str] = field(default_factory=list)  # entries that could not be read
    # zlib-compressed "crc size name" lines of the file entries, for comparison with a published artifact.
    # Compressed, a thousand jars' listings take a few MB.
    listing: bytes | None = None
    # False when the coordinate is the only pom.properties in a jar whose name does not mention it: either the
    # jar was renamed, or the properties belong to a library shaded into it (guice carries only cglib's).
    named_by_file: bool = True


def entries(facts: JarFacts) -> dict[str, tuple[int, int]] | None:
    """File entries of a jar as name -> (CRC-32, uncompressed size), from :attr:`JarFacts.listing`."""
    if facts.listing is None:
        return None
    out = {}
    for line in zlib.decompress(facts.listing).decode("utf-8").splitlines():
        crc, size, name = line.split(" ", 2)
        out[name] = (int(crc, 16), int(size))
    return out


def split_name(filename: str) -> tuple[str, str]:
    """``caffeine-api.hpi`` -> (``caffeine-api``, ``.hpi``); names without a known extension keep their dots."""
    match = ARTIFACT_EXTENSION.search(filename)
    return (filename[:match.start()], match.group(0).lower()) if match else (filename, ".jar")


def file_digests(source: bytes | Path) -> tuple[str, str, int]:
    """SHA-1, SHA-256 and size, reading a file in chunks."""
    sha1, sha256 = hashlib.sha1(), hashlib.sha256()
    if isinstance(source, bytes):
        sha1.update(source)
        sha256.update(source)
        return sha1.hexdigest(), sha256.hexdigest(), len(source)
    size = 0
    with open(source, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
    return sha1.hexdigest(), sha256.hexdigest(), size


def jar_facts(filename: str, source: bytes | Path, digests: tuple[str, str, int] | None = None) -> JarFacts:
    """``source``: the jar's bytes or its path; ``digests`` as :func:`file_digests` returns them, if known."""
    facts = JarFacts(filename, *(digests or file_digests(source)))
    try:
        archive = zipfile.ZipFile(source if isinstance(source, Path) else io.BytesIO(source))
    except (zipfile.BadZipFile, ValueError, OSError):
        facts.readable = False
        return facts
    with archive:
        _read_facts(facts, archive)
    return facts


def _read_facts(facts: JarFacts, archive: zipfile.ZipFile):
    # A name listed twice over different data reads its last listing, as zipfile does.
    by_name = {info.filename: info for info in listed_once(archive)}
    names = list(by_name)

    def read(name: str) -> bytes:
        # A jar with one corrupt or encrypted entry is still a jar: report the entry, keep the rest.
        try:
            return archive.read(by_name[name])
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError) as error:
            facts.damaged.append(f"{name}: {error}")
            return b""

    gavs = []
    for name in names:
        if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
            properties = _properties(read(name))
            g, a, v = (properties.get(k, "").strip() for k in ("groupId", "artifactId", "version"))
            if g and a and v:
                gavs.append((g, a, v, name.rsplit("/", 1)[0]))
    stem = split_name(facts.filename)[0]
    pick = [x for x in gavs if stem == f"{x[1]}-{x[2]}"] or [x for x in gavs if stem.startswith(x[1] + "-")]
    if not pick and len(gavs) == 1:
        pick, facts.named_by_file = gavs, False
    if pick:
        g, a, v, base = pick[0]
        facts.coordinate = (g, a, v)
        facts.embedded = sorted({x[:3] for x in gavs if x[:3] != (g, a, v)})
        if f"{base}/pom.xml" in names:
            found = pom_licenses(read(f"{base}/pom.xml").decode("utf-8", "replace"))
            if found:
                facts.licenses, facts.license_source = found, "jar: pom.xml"
    else:
        # No pom.properties matches the file: every embedded GAV is a candidate, none is the jar itself.
        facts.embedded = sorted({x[:3] for x in gavs})
    if "META-INF/MANIFEST.MF" in names:
        raw = read("META-INF/MANIFEST.MF")
        facts.manifest = {k: v for k in MANIFEST_KEYS if (v := manifest_value(raw, k))}
        if not facts.licenses:
            value = manifest_value(raw, "Bundle-License")
            if value and detect(value):
                facts.licenses, facts.license_source = detect(value), "jar: MANIFEST Bundle-License"
    if not facts.licenses:
        for name in sorted(names, key=len):
            base = posixpath.basename(name).lower()
            if (name.count("/") <= 1 and not name.endswith("/")
                    and re.match(r"(license|licence|copying)([._-].*)?$", base)):
                # Read the whole text: exceptions such as Classpath are appended after the GPL body.
                found = detect(read(name)[:200_000].decode("utf-8", "replace"), first_only=True)
                if found:
                    facts.licenses, facts.license_source = found, f"jar: {name}"
                    break
    _record_listing(facts, archive)
    if NETTY_VERSIONS in names:
        modules = {}
        for key, value in _properties(read(NETTY_VERSIONS)).items():
            if key.endswith(".version"):
                modules[key[: -len(".version")]] = value.strip()
        own = facts.coordinate[1] if facts.coordinate else None
        # Every netty module jar carries this file listing itself; only all-in-one jars list several.
        if len(modules) > 1:
            facts.merged = sorted(("io.netty", artifact, version) for artifact, version in modules.items()
                                  if artifact != own and version)


def version_hints(facts: JarFacts) -> list[str]:
    """Versions a jar suggests for itself: manifest headers, then the tail of its file name.

    Hints only narrow a search; whatever the search returns is accepted only if its published contents match.
    """
    hints = [facts.manifest.get("Implementation-Version"), facts.manifest.get("Bundle-Version")]
    stem = split_name(facts.filename)[0]
    # log4j-1.2-api-2.17.1: a digit after a hyphen does not always start the version, so try every one.
    for match in re.finditer(r"-(?=\d)", stem):
        parts = stem[match.end():].split("-")
        hints += ["-".join(parts[:i]) for i in range(len(parts), 0, -1)]
    return [h for h in dict.fromkeys(hints) if h and re.fullmatch(r"[\w.+-]{1,64}", h)][:8]


def name_hints(facts: JarFacts) -> list[str]:
    """ArtifactIds a jar suggests for itself: its file name without the version, and its manifest title.
    Like :func:`version_hints`, they only say where to look."""
    stem = split_name(facts.filename)[0]
    names = [stem[:-len(v) - 1] for v in version_hints(facts) if stem.endswith("-" + v)]
    names.append(facts.manifest.get("Implementation-Title", ""))
    return [n for n in dict.fromkeys(names) if n and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", n)][:2]


def representative_class(names) -> str | None:
    """A class of the jar's own main package, as a dotted name: the most common three-level package wins,
    so that classes shaded in from other projects are not chosen."""
    classes = [n[:-len(".class")] for n in names if n.endswith(".class") and "$" not in n and "/" in n
               and not n.startswith(("META-INF/", "BOOT-INF/", "WEB-INF/"))
               and posixpath.basename(n) not in ("module-info.class", "package-info.class")]
    if not classes:
        return None
    prefixes = Counter("/".join(c.split("/")[:-1][:3]) for c in classes)
    top = max(prefixes, key=lambda p: (prefixes[p], -len(p), p))
    pick = min((c for c in classes if c.startswith(top + "/")), key=lambda c: (c.count("/"), len(c), c))
    return pick.replace("/", ".")


def _record_listing(facts: JarFacts, archive: zipfile.ZipFile):
    if facts.damaged:
        return
    lines = []
    for info in listed_once(archive):
        if info.is_dir():
            continue
        try:
            # The CRC a zip states is only a claim. A class edited in place with its old CRC left standing
            # still loads (the JVM does not check), so every entry is read and checked before it is trusted.
            with archive.open(info) as stream:
                while stream.read(1 << 20):
                    pass
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError) as error:
            facts.damaged.append(f"{info.filename}: {error}")
            return
        lines.append(f"{info.CRC:08x} {info.file_size} {info.filename}")
    facts.listing = zlib.compress("\n".join(lines).encode("utf-8"))


def _properties(raw: bytes) -> dict[str, str]:
    out = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value
    return out
