"""Scan orchestration: walk inputs, identify components, attach licenses and vulnerabilities."""
from __future__ import annotations

import hashlib
import posixpath
import sys
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from binwitness import __version__, maven, staticjs, vulns
from binwitness.archive import Walker
from binwitness.jar import JarFacts, entries, jar_facts, representative_class, version_hints
from binwitness.licenses import FAMILIES, UNKNOWN, expression_family, family
from binwitness.localdb import OSV_DATASET
from binwitness.net import Net, NetError, OfflineMiss
from binwitness.npm import parse as parse_npm
# The local index lacks some public jars (it keeps one coordinate per file, and Google's repository is not
# Central), so absence from it does not mean that no registry has the file.
OFFLINE_UNKNOWN = "not in the local datasets or the cache; an online scan can tell whether a registry has it"

CONFIDENCE = ("exact", "content", "declared")
# Each candidate costs a checksum and a directory lookup, and the search stops at the first full match.
# bcprov 1.64 needs nine: its debug, ext and JDK-range variants share every class name.
CONTENT_CANDIDATES = 10
# Share of the missing and of the extra entries one package rename must explain before a jar counts as a
# relocated copy of the artifact it declares, rather than a host that shades it.
RELOCATED_SHARE = 0.8
DEPS_DEV = "https://api.deps.dev/v3"


@dataclass
class Options:
    first_party_groups: tuple[str, ...] = ()
    first_party_jars: tuple[str, ...] = ()
    first_party_npm: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    scan_js: bool = True
    licenses: bool = True
    vulnerabilities: bool = True
    # Round-trips dominate a cold scan, and a stalled request holds its worker until the timeout; more
    # workers keep the rest moving (a 190-jar war: 834 s at 8 workers / 120 s timeout, 198 s at 16 / 30 s).
    workers: int = 16
    unpacker: str | None = None
    # Sends one class name per unidentified jar to Maven Central search, so it is opt-in.
    class_search: bool = False


@dataclass
class _Jar:
    facts: JarFacts
    locations: list[str] = field(default_factory=list)


def purl(ecosystem: str, name: str, version: str) -> str:
    quote = urllib.parse.quote
    if ecosystem == "maven":
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{quote(group)}/{quote(artifact)}@{quote(version)}"
    if name.startswith("@") and "/" in name:
        scope, bare = name.split("/", 1)
        return f"pkg:npm/{quote(scope)}/{quote(bare)}@{quote(version)}"
    return f"pkg:npm/{quote(name)}@{quote(version)}"


def _containers(location: str):
    """Locations of the archives a location sits in, outermost first: ``a.zip!/b.jar!/c.jar`` -> a.zip, a.zip!/b.jar."""
    parts = location.split("!/")
    return ("!/".join(parts[:i]) for i in range(1, len(parts)))


class _Components:
    """Components keyed by purl; repeated sightings merge their evidence and locations."""

    def __init__(self):
        self.items: dict[str, dict] = {}

    def add(self, ecosystem, name, version, *, method, confidence, location, scope="unknown", file=None,
            contained_in=None, license_=None):
        key = purl(ecosystem, name, version)
        item = self.items.setdefault(key, {
            "purl": key, "ecosystem": ecosystem, "name": name, "version": version, "scope": None,
            "confidence": confidence, "evidence": [], "locations": [], "files": [], "contained_in": [],
            "declared_license": None, "license": None, "vulnerabilities": []})
        if CONFIDENCE.index(confidence) < CONFIDENCE.index(item["confidence"]):
            item["confidence"] = confidence
        evidence = {"method": method, "confidence": confidence}
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)
        if location not in item["locations"]:
            item["locations"].append(location)
        if file and not any(f["sha1"] == file["sha1"] for f in item["files"]):
            item["files"].append(file)
        if contained_in and contained_in not in item["contained_in"]:
            item["contained_in"].append(contained_in)
        # Shipped if any sighting says so; dev only when every sighting agrees.
        if scope == "runtime" or item["scope"] is None:
            item["scope"] = scope
        elif item["scope"] != scope and item["scope"] != "runtime":
            item["scope"] = "unknown"
        if license_ and not item["declared_license"]:
            item["declared_license"] = license_
        return item


def scan(inputs: list[Path], net: Net, options: Options, log=None, db=None) -> dict:
    """``db``: a :class:`binwitness.localdb.LocalDb`; installed datasets answer before the network."""
    log = log or (lambda message: print(message, file=sys.stderr, flush=True))
    started = datetime.now(timezone.utc)
    walker = Walker(scan_js=options.scan_js, exclude=options.exclude, unpacker=options.unpacker)
    jars: dict[str, _Jar] = {}
    npm_sightings = []
    scripts: dict[str, dict] = {}
    damaged = []
    for path in inputs:
        for item in walker.walk(path):
            if item.kind == "jar":
                sha1 = hashlib.sha1(item.data).hexdigest()
                if sha1 not in jars:
                    facts = jar_facts(posixpath.basename(item.location), item.data)
                    jars[sha1] = _Jar(facts)
                    if facts.damaged:
                        damaged.append(f"{item.location}: unreadable entries: {'; '.join(facts.damaged[:3])}")
                jars[sha1].locations.append(item.location)
            elif item.kind in ("lockfile", "npm-package"):
                for package in parse_npm(posixpath.basename(item.location), item.data):
                    npm_sightings.append((package, item.location))
            elif item.kind == "js":
                digest = hashlib.sha256(item.data).digest()
                entry = scripts.setdefault(digest.hex(), {"digest": digest, "head": item.data[:staticjs.HEAD_SIZE],
                                                          "locations": []})
                entry["locations"].append(item.location)
    log(f"walked {len(inputs)} input(s): {len(jars)} distinct jars, {len(npm_sightings)} npm package entries, "
        f"{len(scripts)} distinct scripts")

    warnings = list(walker.warnings) + damaged
    components = _Components()
    first_party, unidentified = [], []

    def is_first_party_jar(facts: JarFacts, coordinate=None) -> bool:
        group = (coordinate or facts.coordinate or ("",))[0]
        return (group.startswith(options.first_party_groups) if options.first_party_groups and group else False) \
            or (facts.filename.startswith(options.first_party_jars) if options.first_party_jars else False)

    def identify(jar: _Jar):
        facts = jar.facts
        if is_first_party_jar(facts):
            return {"first_party": True}
        try:
            hit = maven.lookup_hash(net, facts.sha1, facts.filename, db, facts.coordinate)
        except OfflineMiss:
            hit, failure = None, OFFLINE_UNKNOWN
        except NetError as error:
            hit, failure = None, str(error)
        else:
            failure = None
        if hit:
            return {"coordinate": hit["coordinate"], "method": f"file SHA-1 matches the published artifact "
                    f"({hit['source']})", "confidence": "exact", "published": "identical",
                    "licenses": hit["licenses"], "alternatives": hit["alternatives"]}
        demoted = None
        if facts.coordinate:
            published, comparison = check_published(facts, facts.coordinate, facts.filename)
            if published == "identical":
                # Neither hash index lists every release (javassist 3.18.1-GA is missing from both), but the
                # checksum Maven Central publishes for the declared coordinates proves the file just as well.
                return {"coordinate": facts.coordinate, "confidence": "exact", "published": "identical",
                        "method": "file SHA-1 equals the checksum Maven Central publishes for the jar's own "
                                  "declared coordinates", "licenses": None}
            if published == "repackaged":
                return {"coordinate": facts.coordinate, "confidence": "content", "published": "repackaged",
                        "comparison": comparison, "licenses": None,
                        "method": "the jar's own pom.properties; every entry but the manifest, index and "
                                  "signatures has the CRC-32 and size of the published artifact's"}
            counts = (comparison or {}).get("counts", {})
            foreign = comparison and comparison["unchanged"] < counts["changed"] + counts["removed"]
            # The declared artifact is all there, but the jar holds more of its own: a host that bundles the
            # library whole (a JDBC driver carrying a compression library), not that library.
            hosting = comparison and counts["added"] > comparison["unchanged"] + counts["changed"]
            moved = ((comparison or {}).get("relocated") or {}).get("entries", 0)
            # Renamed packages and nothing else: a relocated build of the declared library (a vendor's fork
            # of a JDBC driver), so the coordinate still names the jar.
            relocated = (foreign or hosting) and moved >= RELOCATED_SHARE * max(counts["removed"], counts["added"])
            if facts.named_by_file or not (foreign or hosting) or relocated:
                return {"coordinate": facts.coordinate, "method": "the jar's own META-INF/maven pom.properties",
                        "confidence": "declared", "published": published, "comparison": comparison,
                        "licenses": None, "lookup_failure": failure}
            # Most of the published artifact is missing: the properties came with a library shaded into this
            # jar (guice carries only cglib's), so they name a component it contains, not the jar itself.
            demoted = facts.coordinate
        elif facts.embedded and facts.listing is not None:
            found = find_declared(facts)
            if found:
                return {**found, "licenses": None}
        return {"coordinate": None, "lookup_failure": failure, "demoted": demoted}

    def find_declared(facts: JarFacts):
        """Of several pom.properties, none named after the file, the one whose published artifact has this
        jar's entries. A renamed woodstox carries its own and those of the schema libraries it shades."""
        hint = " ".join(facts.manifest.values())
        # The manifest only orders the checks; a candidate counts only if its published entries match.
        for coordinate in sorted(facts.embedded, key=lambda c: c[1] not in hint)[:CONTENT_CANDIDATES]:
            published, comparison = check_published(facts, coordinate, f"{coordinate[1]}-{coordinate[2]}.jar")
            if published in ("identical", "repackaged"):
                how = ("file SHA-1 equals the checksum Maven Central publishes" if published == "identical" else
                       "every entry but the manifest, index and signatures has the CRC-32 and size")
                return {"coordinate": coordinate, "confidence": "exact" if published == "identical" else "content",
                        "published": published, "comparison": comparison,
                        "method": f"{how} of the artifact named by one of the jar's pom.properties"}
        return None

    def check_published(facts: JarFacts, coordinate, filename):
        try:
            published = maven.published_status(net, coordinate, filename, facts.sha1)
            comparison = None
            if published == "differs" and facts.listing is not None:
                comparison = maven.compare_with_published(net, coordinate, filename, entries(facts))
        except NetError:
            return "unchecked", None
        if comparison and not any(comparison["counts"].values()):
            # Every class and resource has the published CRC and size; only the manifest, index or signatures
            # were rewritten. A build that re-zips its dependencies does this.
            published = "repackaged"
        return published, comparison

    def find_by_content(facts: JarFacts):
        local = entries(facts)
        class_name = representative_class(local or {})
        versions = version_hints(facts)
        if not class_name or not versions or (options.first_party_groups
                                              and class_name.startswith(options.first_party_groups)):
            return None
        try:
            candidates = maven.find_by_class(net, class_name, versions)
        except NetError:
            return None
        for coordinate in candidates[:CONTENT_CANDIDATES]:
            published, comparison = check_published(facts, coordinate, f"{coordinate[1]}-{coordinate[2]}.jar")
            if published in ("identical", "repackaged"):
                how = ("file SHA-1 equals the checksum Maven Central publishes" if published == "identical" else
                       "every entry but the manifest, index and signatures has the CRC-32 and size")
                return {"coordinate": coordinate, "confidence": "exact" if published == "identical" else "content",
                        "published": published, "comparison": comparison,
                        "method": f"{how} of the artifact Maven Central lists for class {class_name}"}
        return None

    def match_copies() -> int:
        """Give a jar that nothing identified the coordinate of an identified jar with the same entries.

        A vendor that renames its dependencies and re-zips them without their pom.properties leaves every class
        as it was, and the delivery often carries an untouched copy that a registry did recognise."""
        verified: dict[str, dict] = {}
        for sha1, verdict in verdicts.items():
            if verdict.get("confidence") in ("exact", "content") and not verdict.get("copy_of") \
                    and not is_first_party_jar(jars[sha1].facts, verdict["coordinate"]):
                fingerprint = _content_print(jars[sha1].facts)
                if fingerprint:
                    verified.setdefault(fingerprint, {}).setdefault(verdict["coordinate"], sha1)
        matched = 0
        for sha1, verdict in verdicts.items():
            if verdict.get("coordinate") or verdict.get("first_party"):
                continue
            same = verified.get(_content_print(jars[sha1].facts)) or {}
            if len(same) > 1:
                # Releases that changed nothing but the version (an annotations jar) cannot be told apart.
                verdict["same_content_as"] = sorted(":".join(c) for c in same)
            elif same:
                ((coordinate, original),) = same.items()
                source = verdicts[original]
                verdicts[sha1] = {
                    "coordinate": coordinate, "confidence": "content", "published": "repackaged",
                    "licenses": source.get("licenses"), "alternatives": source.get("alternatives"),
                    "demoted": verdict.get("demoted"), "copy_of": original,
                    "method": f"every entry but the manifest, index and signatures has the CRC-32 and size of "
                              f"{jars[original].facts.filename} in the same delivery, identified as the "
                              f"published artifact"}
                matched += 1
        return matched

    with ThreadPoolExecutor(options.workers) as pool:
        verdicts = dict(zip(jars, pool.map(identify, jars.values())))
    copies = match_copies()
    if options.class_search:
        # After the copies, so that a class name leaves the machine only for a jar nothing else identifies.
        pending = [sha1 for sha1, v in verdicts.items() if not v.get("coordinate") and not v.get("first_party")]
        with ThreadPoolExecutor(options.workers) as pool:
            found = list(pool.map(lambda sha1: find_by_content(jars[sha1].facts), pending))
        for sha1, hit in zip(pending, found):
            if hit:
                verdicts[sha1] = {**hit, "demoted": verdicts[sha1].get("demoted"), "licenses": None}
        if any(found):
            copies += match_copies()
    log(f"identified jars: {sum(1 for v in verdicts.values() if v.get('coordinate'))} of {len(jars)}"
        + (f" ({copies} as copies of others in the delivery)" if copies else ""))

    def is_third_party(sha1):
        verdict = verdicts[sha1]
        return bool(verdict.get("coordinate")) and not is_first_party_jar(jars[sha1].facts, verdict["coordinate"])

    third_party_jar_locations = [loc for sha1, jar in jars.items() if is_third_party(sha1) for loc in jar.locations]

    def inside_third_party(locations):
        return all(any(loc.startswith(parent + "!/") for parent in third_party_jar_locations) for loc in locations)

    published_jar_locations = {loc for sha1, jar in jars.items() if verdicts[sha1].get("published") == "identical"
                               for loc in jar.locations}

    def published_status(verdict, locations):
        # kryo 2.21 as released carries its own builds of minlog and reflectasm. They differ from the files
        # published under those names, but whoever shipped kryo did not change them.
        if verdict["published"] != "identical" and all(
                any(parent in published_jar_locations for parent in _containers(loc)) for loc in locations):
            return "inside-published"
        return verdict["published"]

    jar_hints = {}
    also_published = {}
    resources_of_third_party = 0
    for sha1, jar in jars.items():
        facts, verdict = jar.facts, verdicts[sha1]
        coordinate = verdict.get("coordinate")
        demoted = verdict.get("demoted")
        embedded = [x for x in facts.embedded if x != coordinate] + ([demoted] if demoted and demoted != coordinate else [])
        # A license read from the embedded pom.xml is the shaded library's, not this jar's.
        own_licenses = facts.licenses if not (demoted and facts.license_source == "jar: pom.xml") else []
        parent_label = None
        if not coordinate and inside_third_party(jar.locations):
            # An unrecognised jar shipped inside a recognised library (ehcache's sizeof-agent.jar) is part of it.
            resources_of_third_party += 1
            continue
        if verdict.get("first_party") or (coordinate and is_first_party_jar(facts, coordinate)):
            first_party.append({"filename": facts.filename, "sha1": sha1,
                                "coordinate": ":".join(coordinate or facts.coordinate or ()) or None,
                                "locations": jar.locations})
            parent_label = facts.filename
        elif coordinate:
            file = {"filename": facts.filename, "sha1": sha1, "sha256": facts.sha256,
                    "confidence": verdict["confidence"], "published": published_status(verdict, jar.locations),
                    "locations": jar.locations}
            if verdict.get("comparison"):
                file["comparison"] = verdict["comparison"]
            if verdict.get("copy_of"):
                file["same_entries_as"] = verdict["copy_of"]
            others = [("maven", f"{g}:{a}", v) for g, a, v in verdict.get("alternatives") or []]
            if others:
                file["also_published_as"] = [purl(*other) for other in others]
            for location in jar.locations:
                item = components.add("maven", f"{coordinate[0]}:{coordinate[1]}", coordinate[2],
                                      method=verdict["method"], confidence=verdict["confidence"],
                                      location=location, scope="runtime", file=file)
            if own_licenses:
                item["declared_license"] = {"names": own_licenses, "source": facts.license_source}
            jar_hints[item["purl"]] = verdict.get("licenses")
            known = also_published.setdefault(item["purl"], [])
            known += [other for other in others if other not in known]
            parent_label = item["purl"]
        else:
            reason = (verdict["lookup_failure"] if verdict.get("lookup_failure") == OFFLINE_UNKNOWN
                      else "registry lookup failed: " + verdict["lookup_failure"] if verdict.get("lookup_failure")
                      else "no registry has this file; its entries are those of jars identified as different "
                           "components, listed in same_content_as" if verdict.get("same_content_as")
                      else "no registry has this file; its only pom.properties belongs to a library shaded "
                           "into it" if demoted
                      else "no registry has this file, and it holds no code, only a manifest and license or "
                           "notice files (an empty starter)" if facts.listing is not None
                                                                and _own_entries(facts) is None
                      else "no registry has this file and the jar declares no Maven coordinates")
            unidentified.append({"kind": "jar", "filename": facts.filename, "sha1": sha1, "sha256": facts.sha256,
                                 "size": facts.size, "manifest": facts.manifest, "reason": reason,
                                 "embedded_coordinates": [":".join(g) for g in embedded],
                                 "same_content_as": verdict.get("same_content_as", []),
                                 "license": ({"names": own_licenses, "source": facts.license_source,
                                              "family": family(own_licenses)} if own_licenses else None),
                                 "locations": jar.locations})
            parent_label = facts.filename
        for group, artifact, version in embedded:
            if options.first_party_groups and group.startswith(options.first_party_groups):
                continue
            for location in jar.locations:
                components.add("maven", f"{group}:{artifact}", version, location=location, scope="runtime",
                               method="pom.properties of a library shaded into another jar",
                               confidence="declared", contained_in=parent_label)
        for group, artifact, version in facts.merged:
            for location in jar.locations:
                components.add("maven", f"{group}:{artifact}", version, location=location, scope="runtime",
                               method="module list of an all-in-one artifact (io.netty.versions.properties)",
                               confidence="declared", contained_in=parent_label)

    for package, location in npm_sightings:
        if options.first_party_npm and package.name.startswith(options.first_party_npm):
            continue
        components.add("npm", package.name, package.version, method=f"listed in {package.source}",
                       confidence="declared", location=location, scope=package.scope,
                       license_={"expressions": [package.license], "source": package.source}
                       if package.license else None)

    # Scripts inside an identified third-party jar (webjars, swagger-ui) belong to that jar.
    script_list = [s for s in scripts.values() if not inside_third_party(s["locations"])]
    unmatched_scripts = []
    if script_list:
        def identify_script(entry):
            try:
                return staticjs.identify(net, entry["digest"], entry["head"])
            except NetError as error:
                return {"error": str(error)}
        with ThreadPoolExecutor(options.workers) as pool:
            found = list(pool.map(identify_script, script_list))
        for entry, hit in zip(script_list, found):
            if not hit or "error" in hit:
                unmatched_scripts += entry["locations"]
                if hit:
                    warnings.append(f"script lookup failed: {hit['error']}")
                continue
            for location in entry["locations"]:
                components.add("npm", hit["name"], hit["version"], method=hit["method"],
                               confidence=hit["confidence"], location=location, scope="runtime")
        log(f"scripts matched to npm releases: {sum(1 for h in found if h and 'error' not in h)} "
            f"of {len(script_list)}")

    items = list(components.items.values())
    if options.licenses:
        _attach_licenses(net, items, jar_hints, options.workers, warnings)
    kev_dates = {}
    vulnerabilities = {}
    if options.vulnerabilities:
        vulnerabilities, kev_dates = _attach_vulnerabilities(net, db, items, also_published, options.workers,
                                                             warnings, log)

    items.sort(key=lambda c: (c["ecosystem"], c["name"], c["version"]))
    for item in items:
        item["locations"].sort()
        item["contained_in"].sort()
        item.pop("declared_license", None)
    result = {
        "tool": {"name": "binwitness", "version": __version__},
        "started": started.isoformat(timespec="seconds"),
        "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "inputs": [_describe_input(Path(p)) for p in inputs],
        "options": {"first_party_groups": list(options.first_party_groups),
                    "first_party_jars": list(options.first_party_jars),
                    "first_party_npm": list(options.first_party_npm), "exclude": list(options.exclude),
                    "scan_js": options.scan_js, "class_search": options.class_search, "offline": net.offline,
                    "lookup": "online" if db is None else "local" if net.offline else "auto",
                    "mirrors": dict(net.mirrors)},
        "data_sources": {"online": net.provenance(), "local": db.provenance() if db else {}},
        "summary": {},
        "components": items,
        "first_party": sorted(first_party, key=lambda x: x["filename"]),
        "unidentified": sorted(unidentified, key=lambda x: x["filename"]),
        "unmatched_scripts": sorted(set(unmatched_scripts)),
        "vulnerabilities": dict(sorted(vulnerabilities.items())),
        "warnings": warnings + ([f"offline: {net.offline_misses} lookups were not in the cache ("
                                 + ", ".join(f"{host} {n}" for host, n in net.offline_missed_hosts.most_common())
                                 + ")"] if net.offline_misses else []) + (db.stale() if db else []),
    }
    result["summary"] = summarize(result, len(jars), walker.skipped_runtime_jars, kev_dates)
    result["summary"]["jars"]["inside_identified_libraries"] = resources_of_third_party
    return result


def _own_entries(facts: JarFacts) -> list[tuple[str, int, int]] | None:
    """(name, CRC-32, size) of a jar's entries other than packaging; None when the jar holds nothing that tells
    one artifact from another, or could not be read."""
    listing = entries(facts)
    if not listing:
        return None
    kept = sorted((name, *value) for name, value in listing.items() if not maven.PACKAGING.match(name))
    # Every Spring Boot starter holds the same license and notice and nothing else.
    if not any(name.endswith(".class") or not name.startswith("META-INF/") or name.startswith("META-INF/resources/")
               for name, *_ in kept):
        return None
    return kept


def _content_print(facts: JarFacts) -> str | None:
    kept = _own_entries(facts)
    return hashlib.sha1(repr(kept).encode()).hexdigest() if kept else None


def _attach_licenses(net, items, jar_hints, workers, warnings):
    def resolve(item):
        declared = item["declared_license"]
        try:
            if declared and declared.get("names"):
                return declared
            if declared and declared.get("expressions"):
                return declared
            if item["ecosystem"] == "maven":
                group, artifact = item["name"].split(":", 1)
                return maven.licenses_for(net, (group, artifact, item["version"]), jar_hints.get(item["purl"]))
            quote = urllib.parse.quote
            found = net.get_json(f"{DEPS_DEV}/systems/npm/packages/{quote(item['name'], safe='')}/versions/"
                                 f"{quote(item['version'], safe='')}", stable=True) or {}
            expressions = [e for e in found.get("licenses", []) if e and e.lower() != "non-standard"]
            return {"expressions": expressions, "source": "deps.dev"} if expressions else None
        except OfflineMiss:
            unresolved.append(item["purl"])
            return None
        except NetError as error:
            warnings.append(f"license lookup failed for {item['purl']}: {error}")
            return None

    unresolved = []
    with ThreadPoolExecutor(workers) as pool:
        found_all = list(pool.map(resolve, items))
    # One line for all of them: one per component would bury the other warnings.
    if unresolved:
        warnings.append(f"license unknown for {len(unresolved)} component{'' if len(unresolved) == 1 else 's'}: "
                        "the registry's answer is not in the cache, and this scan does not go online")
    for item, found in zip(items, found_all):
        if not found:
            item["license"] = {"family": UNKNOWN, "source": None}
            continue
        if found.get("expressions"):
            families = [expression_family(e) for e in found["expressions"]]
            known = [FAMILIES.index(f) for f in families if f != UNKNOWN]
            found["family"] = FAMILIES[max(known)] if known else UNKNOWN
        else:
            found["family"] = family(found["names"])
        item["license"] = found


def _attach_vulnerabilities(net, db, items, also_published, workers, warnings, log):
    """``also_published``: purl -> other (ecosystem, name, version) the same file is published under. Their
    advisories apply to the file just as well, and an advisory usually names only one of them."""
    packages = sorted({(c["ecosystem"], c["name"], c["version"]) for c in items}
                      | {other for others in also_published.values() for other in others})
    local = [p for p in packages if db is not None and db.has(OSV_DATASET[p[0]])]
    found, failures = vulns.query(net, [p for p in packages if p not in local], workers=max(workers, 8))
    found.update(vulns.query_local(db, local) if local else {})
    warnings += failures
    try:
        kev_dates = db.kev() if db is not None and db.has("kev") else vulns.kev(net)
    except NetError as error:
        kev_dates = {}
        warnings.append(f"CISA KEV catalog unavailable: {error}")
    table = {}
    for item in items:
        own = (item["ecosystem"], item["name"], item["version"])
        per_key = {}
        for package, record in [(p, r) for p in [own, *also_published.get(item["purl"], [])]
                                for r in found.get(p, [])]:
            key = vulns.key_of(record)
            label, source, vector, score = vulns.severity(record)
            entry = table.setdefault(key, {
                "id": key, "aliases": [], "osv_ids": [], "severity": "UNKNOWN", "severity_source": "none",
                "cvss_vector": None, "cvss_score": None, "summary": vulns.summary(record),
                "published": record.get("published"), "modified": record.get("modified"),
                "malicious": record["id"].startswith("MAL-"), "kev_date_added": None, "affects": {}})
            if record["id"] not in entry["osv_ids"]:
                entry["osv_ids"].append(record["id"])
            entry["aliases"] = sorted(set(entry["aliases"]) | set(record.get("aliases", [])) | {record["id"]}
                                      - {key})
            if vulns.SEVERITIES.index(label) < vulns.SEVERITIES.index(entry["severity"]):
                entry.update(severity=label, severity_source=source, cvss_vector=vector, cvss_score=score)
            elif entry["cvss_vector"] is None and vector:
                entry.update(cvss_vector=vector, cvss_score=score)
            affected = entry["affects"].setdefault(item["purl"], {"fixed": []})
            if package != own and key not in per_key:
                # Fixed versions of the other coordinate, and the reader needs to know which one it was.
                affected["via"] = purl(*package)
            affected["fixed"] = list(dict.fromkeys(affected["fixed"]
                                                   + vulns.fixed_versions(record, package[0], package[1])))
            per_key[key] = entry
        item["vulnerabilities"] = sorted(per_key, key=lambda k: (vulns.SEVERITIES.index(table[k]["severity"]), k))
    for key, entry in table.items():
        cves = [key, *entry["aliases"]]
        entry["kev_date_added"] = next((kev_dates[c] for c in cves if c in kev_dates), None)
    log(f"vulnerabilities: {len(table)} distinct across {sum(1 for c in items if c['vulnerabilities'])} components")
    return table, kev_dates


def summarize(result: dict, distinct_jars: int, skipped_runtime: int, kev_dates: dict) -> dict:
    items, table = result["components"], result["vulnerabilities"]
    return {
        "components": {
            "total": len(items),
            "by_ecosystem": dict(Counter(c["ecosystem"] for c in items)),
            "by_confidence": dict(Counter(c["confidence"] for c in items)),
            "by_scope": dict(Counter(c["scope"] for c in items)),
            "contained_in_other_artifacts": sum(1 for c in items if c["contained_in"] and not c["files"]),
            "with_vulnerabilities": sum(1 for c in items if c["vulnerabilities"]),
        },
        "jars": {
            "distinct_files": distinct_jars,
            "third_party": sum(len(c["files"]) for c in items if c["ecosystem"] == "maven"),
            "first_party": len(result["first_party"]),
            "unidentified": len(result["unidentified"]),
            "differ_from_published": sum(1 for c in items for f in c["files"] if f["published"] == "differs"),
            "repackaged": sum(1 for c in items for f in c["files"] if f["published"] == "repackaged"),
            "copies_of_identified_jars": sum(1 for c in items for f in c["files"] if f.get("same_entries_as")),
            "not_on_central": sum(1 for c in items for f in c["files"] if f["published"] == "not-on-central"),
            "skipped_java_runtime": skipped_runtime,
        },
        "vulnerabilities": {
            "total": len(table),
            "by_severity": {s: sum(1 for v in table.values() if v["severity"] == s) for s in vulns.SEVERITIES},
            "known_exploited": sum(1 for v in table.values() if v["kev_date_added"]),
            "malicious_packages": sum(1 for v in table.values() if v["malicious"]),
        },
        "licenses": {"by_family": dict(Counter((c.get("license") or {}).get("family", UNKNOWN) for c in items))},
        "kev_catalog_entries": len(kev_dates),
    }


def _describe_input(path: Path) -> dict:
    if path.is_dir():
        return {"name": path.name, "type": "directory"}
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return {"name": path.name, "type": "file", "size": path.stat().st_size, "sha256": digest.hexdigest()}
