"""Scan orchestration: walk inputs, identify components, attach licenses and vulnerabilities."""
from __future__ import annotations

import hashlib
import posixpath
import sys
import urllib.parse
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from binwitness import __version__, maven, staticjs, upgrades, vulns
from binwitness.archive import Walker
from binwitness.jar import (JarFacts, entries, file_digests, jar_facts, name_hints, representative_class,
                           split_name, version_hints)
from binwitness.licenses import FAMILIES, UNKNOWN, expression_family, family
from binwitness.localdb import OSV_DATASET
from binwitness.net import Net, NetError, OfflineMiss, map_parallel
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
    # Repositories besides Maven Central that publish releases (milestones, vendors' own); checked after it.
    maven_repos: tuple[str, ...] = ()
    # Advice on which published version leaves the findings behind: two lookups per vulnerable package.
    upgrades: bool = True
    # The lookup mode asked for, as recorded in the result. Not inferable from what was available: asking for
    # local datasets that are not installed leaves no datasets, which is not an online scan.
    lookup: str | None = None


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


def _where(repository: str | None) -> str:
    return "Maven Central" if repository in (None, maven.CENTRAL) else repository


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
        # Shipped if any sighting says so; dev only when every sighting agrees. A sighting without a scope
        # (an installed package.json) does not vote.
        if scope is None:
            pass
        elif scope == "runtime" or item["scope"] is None:
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
        with closing(walker.walk(path)) as items:
            for item in items:
                if item.kind == "jar":
                    digests = file_digests(item.source)
                    sha1 = digests[0]
                    if sha1 not in jars:
                        facts = jar_facts(posixpath.basename(item.location), item.source, digests)
                        jars[sha1] = _Jar(facts)
                        if facts.damaged:
                            damaged.append(f"{item.location}: unreadable entries: {'; '.join(facts.damaged[:3])}")
                    jars[sha1].locations.append(item.location)
                elif item.kind in ("lockfile", "npm-package"):
                    data = item.read()
                    packages = parse_npm(posixpath.basename(item.location), data)
                    # A lockfile of a project without dependencies is a few hundred bytes.
                    if item.kind == "lockfile" and not packages and len(data) > 2048:
                        damaged.append(f"{item.location}: no packages could be read from this lockfile")
                    npm_sightings += [(package, item.location) for package in packages]
                elif item.kind == "js":
                    data = item.read()
                    digest = hashlib.sha256(data).digest()
                    entry = scripts.setdefault(digest.hex(), {"digest": digest, "head": data[:staticjs.HEAD_SIZE],
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
            published, comparison, repository = check_published(facts, facts.coordinate, facts.filename)
            if published == "identical":
                # Neither hash index lists every release (javassist 3.18.1-GA is missing from both), but the
                # checksum a repository publishes for the declared coordinates proves the file just as well.
                return {"coordinate": facts.coordinate, "confidence": "exact", "published": "identical",
                        "repository": repository, "licenses": None,
                        "method": f"file SHA-1 equals the checksum {_where(repository)} publishes for the jar's "
                                  f"own declared coordinates"}
            if published == "repackaged":
                return {"coordinate": facts.coordinate, "confidence": "content", "published": "repackaged",
                        "comparison": comparison, "repository": repository, "licenses": None,
                        "method": f"the jar's own pom.properties; every entry but {maven.PACKAGING_TEXT} has the "
                                  f"CRC-32 and size of the artifact {_where(repository)} publishes"}
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
                        "repository": repository, "licenses": None, "lookup_failure": failure}
            # Most of the published artifact is missing: the properties came with a library shaded into this
            # jar (guice carries only cglib's), so they name a component it contains, not the jar itself.
            demoted = facts.coordinate
        elif facts.embedded and facts.listing is not None:
            found = find_declared(facts)
            if found:
                return {**found, "licenses": None}
        return {"coordinate": None, "lookup_failure": failure, "demoted": demoted}

    def published_name(facts: JarFacts, coordinate) -> str:
        return f"{coordinate[1]}-{coordinate[2]}{split_name(facts.filename)[1]}"

    def match(facts: JarFacts, coordinate, found_by: str):
        published, comparison, repository = check_published(facts, coordinate, published_name(facts, coordinate))
        if published not in ("identical", "repackaged"):
            return None
        how = (f"file SHA-1 equals the checksum {_where(repository)} publishes" if published == "identical"
               else f"every entry but {maven.PACKAGING_TEXT} has the CRC-32 and size of what "
                    f"{_where(repository)} publishes")
        return {"coordinate": coordinate, "confidence": "exact" if published == "identical" else "content",
                "published": published, "comparison": comparison, "repository": repository,
                "method": f"{how} for the artifact {found_by}"}

    def first_match(facts: JarFacts, candidates, found_by: str):
        """The candidate coordinate whose published artifact this jar is, or holds the entries of.

        Projects republish libraries under their own groupId with the classes unchanged (org.lucee has
        commons-collections 3.2.1), and a class search may list such a copy first. Once one candidate matches,
        the others of the same artifact and version are checked too: the closest names the jar, and the rest
        become ``alternatives``, so that advisories filed against the original still count."""
        candidates = list(candidates)
        for index, coordinate in enumerate(candidates):
            found = match(facts, coordinate, found_by)
            if not found:
                continue
            same = [match(facts, other, found_by) for other in candidates[index + 1:] if other[1:] == coordinate[1:]]
            matches = [found, *(m for m in same if m)]
            best = min(matches, key=lambda m: (m["published"] != "identical",
                                               len((m["comparison"] or {}).get("packaging_only", []))))
            if len(matches) > 1:
                best["alternatives"] = [m["coordinate"] for m in matches if m is not best]
            return best
        return None

    def find_declared(facts: JarFacts):
        """Of several pom.properties, none named after the file, the one whose published artifact has this
        jar's entries. A renamed woodstox carries its own and those of the schema libraries it shades."""
        hint = " ".join(facts.manifest.values())
        # The manifest only orders the checks; a candidate counts only if its published entries match.
        candidates = sorted(facts.embedded, key=lambda c: c[1] not in hint)[:CONTENT_CANDIDATES]
        return first_match(facts, candidates, "named by one of the jar's pom.properties")

    def check_published(facts: JarFacts, coordinate, filename):
        """(status, entry comparison, repository that publishes the artifact)."""
        try:
            published, repository = maven.published_status(net, coordinate, filename, facts.sha1,
                                                            options.maven_repos)
            comparison = None
            if published == "differs" and facts.listing is not None:
                comparison = maven.compare_with_published(net, coordinate, filename, entries(facts), repository)
        except NetError:
            return "unchecked", None, None
        if comparison and not any(comparison["counts"].values()):
            # Every class and resource has the published CRC and size; only packaging (manifest, index,
            # signatures, Maven metadata) was rewritten. A build that re-zips its dependencies does this.
            published = "repackaged"
        return published, comparison, repository

    def find_by_content(facts: JarFacts):
        local = entries(facts)
        class_name = representative_class(local or {})
        versions = version_hints(facts)
        if not class_name or not versions or (options.first_party_groups
                                              and class_name.startswith(options.first_party_groups)):
            return None
        tried = []

        def attempt(candidates, found_by):
            fresh = [c for c in dict.fromkeys(candidates) if c not in tried][:CONTENT_CANDIDATES]
            tried.extend(fresh)
            return first_match(facts, fresh, found_by) if fresh else None

        stages = [
            (lambda: maven.find_by_class(net, class_name, versions), f"Maven Central lists for class {class_name}"),
            # Central's class index misses releases (spring-context 6.2.0-RC1 lists only a Camel wrapper), and
            # its search service throttles. The jar's own name and its siblings' groupIds need neither.
            (lambda: guessed_coordinates(facts, class_name, versions), "named by the jar's file name or manifest"),
        ]
        if options.maven_repos:
            # A release published only on another repository (a milestone): Central's index knows the
            # artifact from its other releases, and the jar's version hints name the release to fetch.
            stages.append((lambda: [(g, a, v) for g, a in maven.find_artifacts_by_class(net, class_name)[:3]
                                    for v in versions[:3]],
                           f"Maven Central lists for class {class_name} in other releases"))
        for candidates, found_by in stages:
            try:
                found = attempt(candidates(), found_by)
            except NetError:
                continue
            if found:
                return found
        return None

    def guessed_coordinates(facts: JarFacts, class_name: str, versions: list[str]):
        """groupIds from the class's package and from identified jars of the same family (spring-jcl's classes
        are org.apache.commons.logging, but spring-core beside it is org.springframework)."""
        package = class_name.split(".")[:-1]
        from_package = [".".join(package[:n]) for n in (3, 2) if len(package) >= n]
        guesses = []
        for artifact in name_hints(facts):
            siblings = [g for g, _ in families.get(artifact.split("-")[0], Counter()).most_common(3)]
            groups = sorted(dict.fromkeys(from_package + siblings),
                            key=lambda g: (not (g in siblings and g in from_package), g not in from_package))
            guesses += [(g, artifact, v) for g in groups for v in versions[:2]]
        return guesses

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
                    "demoted": verdict.get("demoted"), "copy_of": original, "repository": source.get("repository"),
                    "method": f"every entry but {maven.PACKAGING_TEXT} has the CRC-32 and size of "
                              f"{jars[original].facts.filename} in the same delivery, identified as the "
                              f"published artifact"}
                matched += 1
        return matched

    verdicts = dict(zip(jars, map_parallel(identify, jars.values(), options.workers)))
    copies = match_copies()
    # A second round when the first identified anything: spring-core found on a milestone repository names the
    # groupId spring-jcl's guesses need. The lookups of the first round are answered from the cache.
    for _ in range(2 if options.class_search else 0):
        families: dict[str, Counter] = {}
        for verdict in verdicts.values():
            if verdict.get("coordinate"):
                group, artifact, _ = verdict["coordinate"]
                families.setdefault(artifact.split("-")[0], Counter())[group] += 1
        # After the copies, so that a class name leaves the machine only for a jar nothing else identifies.
        pending = [sha1 for sha1, v in verdicts.items() if not v.get("coordinate") and not v.get("first_party")]
        found = map_parallel(lambda sha1: find_by_content(jars[sha1].facts), pending, options.workers)
        for sha1, hit in zip(pending, found):
            if hit:
                verdicts[sha1] = {**hit, "demoted": verdicts[sha1].get("demoted"), "licenses": None}
        if not any(found):
            break
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
            first_party.append({"filename": facts.filename, "sha1": sha1, "sha256": facts.sha256,
                                "coordinate": ":".join(coordinate or facts.coordinate or ()) or None,
                                "locations": jar.locations})
            parent_label = facts.filename
        elif coordinate:
            file = {"filename": facts.filename, "sha1": sha1, "sha256": facts.sha256,
                    "confidence": verdict["confidence"], "published": published_status(verdict, jar.locations),
                    "locations": jar.locations}
            if verdict.get("repository") not in (None, maven.CENTRAL):
                file["repository"] = verdict["repository"]
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
            reason = ("not a readable zip archive (truncated, damaged or not a jar at all)" if not facts.readable
                      else verdict["lookup_failure"] if verdict.get("lookup_failure") == OFFLINE_UNKNOWN
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
                                 "hint": _manifest_hint(facts),
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
    looked_up, project_scripts = [], []
    for entry in script_list:
        (looked_up if staticjs.worth_looking_up(entry["locations"], entry["head"]) else project_scripts).append(entry)
    script_list = looked_up
    declared_npm: dict[str, set] = {}
    for package, _ in npm_sightings:
        declared_npm.setdefault(package.name, set()).add(package.version)
    unmatched_scripts, bundled_scripts, unpinned_scripts = [], [], []
    scripts_not_looked_up = matched_scripts = 0
    if script_list:
        def identify_script(entry):
            try:
                return staticjs.identify(net, entry["digest"], entry["head"], declared_npm)
            except NetError as error:
                return {"error": str(error)}
        found = map_parallel(identify_script, script_list, options.workers)
        for entry, hit in zip(script_list, found):
            if hit and "error" in hit:
                unmatched_scripts += entry["locations"]
                warnings.append(f"script lookup failed: {hit['error']}")
                scripts_not_looked_up += 1
            elif not hit:
                (bundled_scripts if staticjs.is_bundle(entry["locations"], entry["head"])
                 else unmatched_scripts).extend(entry["locations"])
            elif hit.get("version") is None and not hit.get("versions"):
                unpinned_scripts.append({"package": hit["name"], "file": hit["file"],
                                         "same_file_in": hit["same_file_in"], "reason": hit["reason"],
                                         "locations": sorted(entry["locations"])})
            else:
                matched_scripts += len(entry["locations"])
                for version in hit.get("versions") or [hit["version"]]:
                    for location in entry["locations"]:
                        components.add("npm", hit["name"], version, method=hit["method"],
                                       confidence=hit["confidence"], location=location, scope="runtime")
        log(f"scripts matched to npm releases: {sum(1 for h in found if h and (h.get('version') or h.get('versions')))}"
            f" of {len(script_list)} looked up; {len(project_scripts)} project files not looked up")
    if walker.skipped_caches:
        log(f"skipped {len(walker.skipped_caches)} build cache director"
            f"{'y' if len(walker.skipped_caches) == 1 else 'ies'}: {', '.join(walker.skipped_caches[:3])}"
            + (f" and {len(walker.skipped_caches) - 3} more" if len(walker.skipped_caches) > 3 else ""))
    for ecosystem, found_at in sorted(walker.not_covered.items()):
        warnings.append(f"{ecosystem} dependency files found ({', '.join(found_at[:3])}"
                        + (f" and {len(found_at) - 3} more" if len(found_at) > 3 else "")
                        + f"): binwitness reads Java archives and npm packages only, so {ecosystem} dependencies "
                          "are not in this result")

    items = list(components.items.values())
    for item in items:
        item["scope"] = item["scope"] or "unknown"
    licenses_not_looked_up = 0
    if options.licenses:
        licenses_not_looked_up = _attach_licenses(net, items, jar_hints, options.workers, warnings,
                                                  options.maven_repos)
    kev_dates = {}
    vulnerabilities = {}
    kev_available = True
    if options.vulnerabilities:
        vulnerabilities, kev_dates, kev_available = _attach_vulnerabilities(net, db, items, also_published,
                                                                            options.workers, warnings, log)
    upgrades_not_checked = 0
    families: list[dict] = []
    if options.vulnerabilities and options.upgrades:
        upgrades_not_checked = upgrades.attach(net, db, items, vulnerabilities, options.maven_repos, options.workers,
                                               warnings, log, families)
        if options.licenses:
            def target_license(ecosystem, name, version):
                try:
                    return _declared_license(net, ecosystem, name, version, repositories=options.maven_repos)
                except NetError:
                    return None
            upgrades.note_license_changes(items, families, target_license, options.workers)
    if not (jars or npm_sightings or scripts):
        warnings.append("nothing to identify: the inputs hold no jar, npm lockfile, node_modules package or "
                        "JavaScript file that binwitness reads")

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
                    "scan_js": options.scan_js, "licenses": options.licenses,
                    "vulnerabilities": options.vulnerabilities,
                    "upgrades": options.vulnerabilities and options.upgrades, "class_search": options.class_search,
                    "maven_repos": list(options.maven_repos), "offline": net.offline,
                    "lookup": options.lookup or ("online" if db is None else "local" if net.offline else "auto"),
                    "mirrors": dict(net.mirrors)},
        "data_sources": {"online": net.provenance(), "local": db.provenance() if db else {}},
        "summary": {},
        "components": items,
        "first_party": sorted(first_party, key=lambda x: x["filename"]),
        "unidentified": sorted(unidentified, key=lambda x: x["filename"]),
        "unmatched_scripts": sorted(set(unmatched_scripts)),
        "bundled_scripts": sorted(set(bundled_scripts)),
        "scripts_without_version": sorted(unpinned_scripts, key=lambda x: (x["package"], x["locations"])),
        "project_scripts": sorted(location for entry in project_scripts for location in entry["locations"]),
        "not_covered": {ecosystem: sorted(found_at) for ecosystem, found_at in sorted(walker.not_covered.items())},
        "skipped_build_caches": walker.skipped_caches,
        "vulnerabilities": dict(sorted(vulnerabilities.items())),
        "upgrade_families": families,
        "warnings": warnings + ([f"offline: {net.offline_misses} lookups were not in the cache ("
                                 + ", ".join(f"{host} {n}" for host, n in net.offline_missed_hosts.most_common())
                                 + ")"] if net.offline_misses else []) + (db.stale() if db else []),
    }
    result["summary"] = summarize(result, len(jars), walker.skipped_runtime_jars, kev_dates,
                                  resources_of_third_party)
    result["summary"]["scripts"] = {
        "matched": matched_scripts,
        "version_not_determined": sum(len(x["locations"]) for x in unpinned_scripts),
        "bundles": len(result["bundled_scripts"]),
        "unmatched": len(result["unmatched_scripts"]),
        "project_files_not_looked_up": len(result["project_scripts"]),
    }
    incomplete = {
        "jars_not_looked_up": sum(1 for u in result["unidentified"]
                                  if u["reason"] == OFFLINE_UNKNOWN or u["reason"].startswith("registry lookup failed")),
        "scripts_not_looked_up": scripts_not_looked_up,
        "jar_files_not_compared": sum(1 for c in items for f in c["files"] if f["published"] == "unchecked"),
        "vulnerabilities_not_checked": sum(1 for c in items if c.get("vulnerabilities_checked") is False),
        "licenses_not_looked_up": licenses_not_looked_up,
        "kev_catalog_unavailable": options.vulnerabilities and not kev_available,
        "upgrade_versions_not_checked": upgrades_not_checked,
    }
    result["summary"]["incomplete"] = {k: v for k, v in incomplete.items() if v}
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


def _manifest_hint(facts: JarFacts) -> str | None:
    """What the manifest says the jar is. Anyone can write a manifest, so it only points where to look."""
    name = facts.manifest.get("Implementation-Title") or facts.manifest.get("Bundle-SymbolicName") \
        or facts.manifest.get("Automatic-Module-Name")
    version = facts.manifest.get("Implementation-Version") or facts.manifest.get("Bundle-Version")
    return " ".join(x for x in (name, version) if x) or None


def _attach_licenses(net, items, jar_hints, workers, warnings, repositories=()) -> int:
    """Sets each item's ``license``; returns how many could not be looked up."""
    def resolve(item):
        declared = item["declared_license"]
        try:
            if declared and (declared.get("names") or declared.get("expressions")):
                return declared
            return _declared_license(net, item["ecosystem"], item["name"], item["version"],
                                     jar_hints.get(item["purl"]), repositories)
        except OfflineMiss:
            unresolved.append(item["purl"])
            return None
        except NetError as error:
            warnings.append(f"license lookup failed for {item['purl']}: {error}")
            failed.append(item["purl"])
            return None

    unresolved, failed = [], []
    found_all = map_parallel(resolve, items, workers)
    # One line for all of them: one per component would bury the other warnings.
    if unresolved:
        warnings.append(f"license unknown for {len(unresolved)} component{'' if len(unresolved) == 1 else 's'}: "
                        "the registry's answer is not in the cache, and this scan does not go online")
    for item, found in zip(items, found_all):
        item["license"] = _classified(found) if found else {"family": UNKNOWN, "source": None}
    return len(unresolved) + len(failed)


def _declared_license(net, ecosystem, name, version, hint=None, repositories=()) -> dict | None:
    """The registry's license declaration of a published version, with its family."""
    if ecosystem == "maven":
        group, artifact = name.split(":", 1)
        found = maven.licenses_for(net, (group, artifact, version), hint, repositories)
    else:
        quote = urllib.parse.quote
        answer = net.get_json(f"{DEPS_DEV}/systems/npm/packages/{quote(name, safe='')}/versions/"
                              f"{quote(version, safe='')}", stable=True) or {}
        expressions = [e for e in answer.get("licenses", []) if e and e.lower() != "non-standard"]
        found = {"expressions": expressions, "source": "deps.dev"} if expressions else None
    return _classified(found) if found else None


def _classified(found: dict) -> dict:
    if found.get("expressions"):
        known = [FAMILIES.index(f) for f in map(expression_family, found["expressions"]) if f != UNKNOWN]
        found["family"] = FAMILIES[max(known)] if known else UNKNOWN
    else:
        found["family"] = family(found["names"])
    return found


def _attach_vulnerabilities(net, db, items, also_published, workers, warnings, log):
    """``also_published``: purl -> other (ecosystem, name, version) the same file is published under. Their
    advisories apply to the file just as well, and an advisory usually names only one of them."""
    packages = sorted({(c["ecosystem"], c["name"], c["version"]) for c in items}
                      | {other for others in also_published.values() for other in others})
    local = [p for p in packages if db is not None and db.has(OSV_DATASET[p[0]])]
    found, failures, incomplete = vulns.query(net, [p for p in packages if p not in local],
                                              workers=max(workers, 8))
    found.update(vulns.query_local(db, local) if local else {})
    warnings += failures
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
        # An empty list from a failed lookup would read as "no known vulnerabilities".
        item["vulnerabilities_checked"] = not any(p in incomplete
                                                  for p in [own, *also_published.get(item["purl"], [])])
    kev_dates, kev_available = {}, True
    # The catalog is a megabyte; without findings there is nothing to look up in it.
    if table:
        try:
            kev_dates = db.kev() if db is not None and db.has("kev") else vulns.kev(net)
        except NetError as error:
            kev_available = False
            warnings.append(f"CISA KEV catalog unavailable: {error}")
    for key, entry in table.items():
        cves = [key, *entry["aliases"]]
        entry["kev_date_added"] = next((kev_dates[c] for c in cves if c in kev_dates), None)
    log(f"vulnerabilities: {len(table)} distinct across {sum(1 for c in items if c['vulnerabilities'])} components")
    return table, kev_dates, kev_available


def summarize(result: dict, distinct_jars: int, skipped_runtime: int, kev_dates: dict,
              inside_identified: int = 0) -> dict:
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
            "inside_identified_libraries": inside_identified,
            "skipped_java_runtime": skipped_runtime,
        },
        "vulnerabilities": {
            "total": len(table),
            "by_severity": {s: sum(1 for v in table.values() if v["severity"] == s) for s in vulns.SEVERITIES},
            "known_exploited": sum(1 for v in table.values() if v["kev_date_added"]),
            "malicious_packages": sum(1 for v in table.values() if v["malicious"]),
        },
        "licenses": {"by_family": dict(Counter((c.get("license") or {}).get("family", UNKNOWN) for c in items))},
        "upgrades": {
            "by_verdict": {v: n for v in upgrades.VERDICTS
                           if (n := sum(1 for c in items if (c.get("upgrade") or {}).get("verdict") == v))},
            "fix_versions_not_published": sum(len((c.get("upgrade") or {}).get("fix_versions_not_published") or [])
                                              for c in items),
            "families": len(result.get("upgrade_families") or []),
        },
        "kev_catalog_entries": len(kev_dates),
    }


def _describe_input(path: Path) -> dict:
    if path.is_dir():
        # "." has no name of its own.
        return {"name": path.name or path.resolve().name or str(path), "type": "directory"}
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return {"name": path.name, "type": "file", "size": path.stat().st_size, "sha256": digest.hexdigest()}
