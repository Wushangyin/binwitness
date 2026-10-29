"""Upgrade advice: for a vulnerable component, the nearest published version that its package's own
advisories no longer name.

Every advisory of the package is weighed, not only those that name the version in use: a later release can
sit inside an advisory that the current one predates. Candidates come from the registry's list of published
versions, never from the advisories' "fixed" values alone, which name versions that were never published
(jetty-security 9.4.63, the 9.4 line ended at 9.4.58) or that belong to another coordinate (log4j:log4j
"2.0" lives at org.apache.logging.log4j). The advice states what the advisories say about a version; it
does not judge API compatibility, and it does not judge whether the vulnerable code is reachable.
"""
from __future__ import annotations

import functools
import re
import urllib.parse
from dataclasses import dataclass, field

from binwitness import vulns
from binwitness.licenses import FAMILIES, UNKNOWN
from binwitness.localdb import OSV_DATASET
from binwitness.maven import CENTRAL
from binwitness.net import Net, NetError, OfflineMiss, map_parallel
from binwitness.versions import compare, prerelease, variant, without_variant

NPM_REGISTRY = "https://registry.npmjs.org"
# The abbreviated document lists versions and deprecations without readmes: kilobytes instead of megabytes.
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"
VERDICTS = ("remove-malicious", "upgrade", "upgrade-across-major", "relocated", "partial", "no-published-fix",
            "unverified")
VERDICT_TEXT = {
    "remove-malicious": "malicious package: remove it; no version of it is an upgrade",
    "upgrade": "a later release on the same line is outside every advisory of this package",
    "upgrade-across-major": "only a later major line leaves out more advisories; compatibility is not assessed",
    "relocated": "the package moved to new coordinates, and a release there leaves out more advisories than any "
                 "release of the old ones",
    "partial": "the best release on this line still falls inside some advisories, and no other line does better",
    "no-published-fix": "no published version of this coordinate leaves out more advisories: replace or remove it",
    "unverified": "the version list or the advisories could not be read, so no version was checked",
}
CAVEATS = {
    "embedded-in-host": "bundled inside {hosts}: the change has to come from a release of the host, and the "
                        "host's newer releases may bundle a different version; check what they bundle",
    "modified-jar": "the delivered jar differs from the published one and may carry local changes that the "
                    "published version lacks",
    "coordinates-unverified": "the coordinates come from the jar's own metadata, not from a registry match; "
                              "confirm them before relying on this advice",
    "via-alias": "some advisories name another coordinate this file is published under ({via}); their fixed "
                 "versions are listed separately and are not used as the target",
    "prerelease-only": "a pre-release ({version}) leaves out more advisories than any final release",
    "dev-dependency": "marked as a development dependency in the lockfile; it may not ship with the product",
    "flavor-choice": "the target is a variant build ({variants}) and the version in use is not; variants differ in "
                     "platform or features, so check which one fits",
    "flavor-dropped": "the target is not a {variant} build like the version in use",
    "compatibility-not-assessed": "the target is on a later major line: API changes, renamed packages (javax to "
                                  "jakarta) and a newer minimum runtime are not assessed",
    "range-unreadable": "OSV reports {ids} for this version, but binwitness cannot evaluate their version ranges; "
                        "they are counted as remaining in every candidate",
    "local-version-list": "versions as of the local hash index ({as_of}); later releases are not in it",
    "relocated": "{moved_by} relocates the artifact to {package}: later releases are published there",
    "license-changes": "the target is licensed differently: {changes}; read the new terms before upgrading",
    "family-ends": "some members are not published at later versions ({members}; the latest of the others is "
                   "{latest}), so a version they all share is no later than their last release",
}


@dataclass
class Listing:
    """Published versions of a package, or why there are none."""
    versions: list[str] | None
    deprecated: frozenset = frozenset()
    source: dict = field(default_factory=dict)
    error: str | None = None


def caveat(code: str, **values) -> dict:
    return {"code": code, "text": CAVEATS[code].format(**values), **values}


def line_of(ecosystem: str, version: str):
    """Release line: the major version. Calendar versions (20231013) form one line, and an npm 0.y line
    makes no compatibility promise beyond itself."""
    numbers = [int(n) for n in re.findall(r"\d+", version)[:2]] or [0]
    if numbers[0] >= 1000:
        return "calendar"
    if ecosystem == "npm" and numbers[0] == 0:
        return (0, numbers[1] if len(numbers) > 1 else 0)
    return (numbers[0],)


def is_published(ecosystem: str, fixed: str, versions: list[str]) -> bool:
    """Advisories name a release by its number alone: "9.4.56" is published as 9.4.56.v20240826, "33.7.2" as
    33.7.2-jre and 33.7.2-android, "4.1.44" as 4.1.44.Final."""
    return any(compare(ecosystem, fixed, v) == 0
               or (v.startswith(fixed) and re.match(r"[.-][A-Za-z]", v[len(fixed):])) for v in versions)


def _weight(keys, severity_of: dict) -> tuple:
    """Fewer critical first, then fewer high, and so on; an unrated advisory counts as medium."""
    levels = [severity_of.get(k, "UNKNOWN") for k in keys]
    return (levels.count("CRITICAL"), levels.count("HIGH"), levels.count("MEDIUM") + levels.count("UNKNOWN"),
            levels.count("LOW"))


class _Advisories:
    """Every advisory of one package, read against any version of it."""

    def __init__(self, ecosystem: str, name: str, version: str, records: list[dict],
                 reported: dict[str, dict] | None = None):
        self.ecosystem, self.name = ecosystem, name
        reported = reported or {}
        self.by_key: dict[str, list[dict]] = {}
        for record in records:
            if not record.get("withdrawn"):
                self.by_key.setdefault(vulns.key_of(record), []).append(record)
        self.severity_of = {k: min((vulns.severity(r)[0] for r in rs), key=vulns.SEVERITIES.index)
                            for k, rs in self.by_key.items()}
        self.severity_of.update({k: v["severity"] for k, v in reported.items() if k not in self.severity_of})
        self.matched = functools.cache(self._matched)
        # OSV's own matching named these for the version in use, but their ranges do not read that way here.
        # Counting them in every candidate keeps the advice from claiming a fix it cannot show.
        self.unread = frozenset(k for k in reported if k not in self.matched(version))

    def _matched(self, candidate: str) -> frozenset:
        return frozenset(k for k, rs in self.by_key.items()
                         if any(vulns.affects(r, self.ecosystem, self.name, candidate) for r in rs))

    def hits(self, candidate: str) -> frozenset:
        return self.matched(candidate) | self.unread


def _best(choices, hits, severity_of) -> tuple[str, tuple] | None:
    found = None
    for candidate in choices:
        weight = _weight(hits(candidate), severity_of)
        if found is None or weight < found[1]:
            found = (candidate, weight)
            # Candidates come in ascending order: the first one outside every advisory is the nearest.
            if not any(weight):
                break
    return found


def _choose(ecosystem: str, version: str, pool: list[str], hits, severity_of) -> tuple:
    """Verdict, target and the best candidate on the line in use, from ``pool`` in ascending order."""
    home = line_of(ecosystem, version)
    same_line = _best([v for v in pool if line_of(ecosystem, v) == home], hits, severity_of)
    anywhere = _best(pool, hits, severity_of)
    now = _weight(hits(version), severity_of)
    if same_line and not any(same_line[1]):
        return "upgrade", same_line[0], same_line
    if anywhere and anywhere[1] < (same_line[1] if same_line else now):
        return "upgrade-across-major", anywhere[0], same_line
    if same_line and same_line[1] < now:
        return "partial", same_line[0], same_line
    return "no-published-fix", None, same_line


def advise(ecosystem: str, name: str, version: str, records: list[dict], listing: Listing,
           reported: dict[str, dict] | None = None) -> dict:
    """The upgrade block for one component. ``records``: every OSV record of the package. ``reported``: the
    scan's findings for this version from the package's own advisories, id -> table entry."""
    reported = reported or {}
    package = _Advisories(ecosystem, name, version, records, reported)
    by_key, severity_of, hits, unread = package.by_key, package.severity_of, package.hits, package.unread
    current = hits(version)
    ordered = functools.partial(sorted, key=lambda k: (vulns.SEVERITIES.index(severity_of.get(k, "UNKNOWN")), k))
    fixed = {k: [f for r in by_key.get(k, []) for f in vulns.fixed_versions(r, ecosystem, name)
                 if compare(ecosystem, f, version) > 0] for k in ordered(current)}
    fixed = {k: list(dict.fromkeys(v)) for k, v in fixed.items() if v}
    block = {"verdict": None, "target": None, "clears": [], "remaining": ordered(current), "introduced": [],
             "caveats": [caveat("range-unreadable", ids=", ".join(ordered(unread)))] if unread else []}

    if any(k.startswith("MAL-") or reported.get(k, {}).get("malicious")
           or any(r["id"].startswith("MAL-") for r in by_key.get(k, [])) for k in current):
        return block | {"verdict": "remove-malicious"}
    if listing.versions is None:
        return block | {"verdict": "unverified", "reason": listing.error, "osv_fixed": fixed}
    if current and current == unread:
        return block | {"verdict": "unverified", "caveats": [],
                        "reason": "none of the package's OSV records reads as covering this version, although "
                                  f"OSV reports {', '.join(ordered(unread))} for it"}
    block["versions_source"] = listing.source

    order = functools.cmp_to_key(lambda a, b: compare(ecosystem, a, b))
    newer = sorted({v for v in listing.versions if compare(ecosystem, v, version) > 0} - listing.deprecated, key=order)
    own_variant = variant(ecosystem, version)

    def fits(candidate):
        other = variant(ecosystem, candidate)
        return other is None or own_variant is None or other == own_variant

    on_prerelease = prerelease(ecosystem, version)
    pool = [v for v in newer if fits(v) and (on_prerelease or not prerelease(ecosystem, v))]
    verdict, target, same_line = _choose(ecosystem, version, pool, hits, severity_of)
    now = _weight(current, severity_of)

    def outcome(candidate):
        found = hits(candidate)
        return {"clears": ordered(current - found), "remaining": ordered(current & found),
                "introduced": ordered(found - current)}

    block.update(verdict=verdict, target=target)
    if target:
        block.update(outcome(target))
    if verdict == "upgrade-across-major":
        block["caveats"].append(caveat("compatibility-not-assessed"))
        if same_line and same_line[1] < now:
            block["same_line"] = {"target": same_line[0], **outcome(same_line[0])}
    if target and variant(ecosystem, target) != own_variant:
        if own_variant is None:
            alternatives = [v for v in pool if v != target and without_variant(v) == without_variant(target)
                            and variant(ecosystem, v) and hits(v) == hits(target)]
            block["alternatives"] = alternatives
            block["caveats"].append(caveat("flavor-choice", variants=", ".join([target, *alternatives])))
        else:
            block["caveats"].append(caveat("flavor-dropped", variant=own_variant))
    if verdict != "upgrade" and not on_prerelease:
        leftover = _weight(hits(target), severity_of) if target else now
        early = _best([v for v in newer if fits(v) and prerelease(ecosystem, v)], hits, severity_of)
        if early and early[1] < leftover:
            block["caveats"].append(caveat("prerelease-only", version=early[0]))
    if verdict == "no-published-fix":
        block["osv_fixed"] = fixed
    block["fix_versions_not_published"] = [{"id": k, "fixed": f} for k, values in fixed.items() for f in values
                                           if not is_published(ecosystem, f, listing.versions)]
    as_of = listing.source.get("as_of")
    if as_of:
        missing = list(dict.fromkeys(x["fixed"] for x in block["fix_versions_not_published"]))
        if verdict == "no-published-fix" and missing:
            # The index stops at its build date and holds jars only; from it alone "never published" and
            # "published since" look the same.
            return block | {"verdict": "unverified", "target": None,
                            "reason": f"the fixed version{'s' if len(missing) > 1 else ''} named by the advisories "
                                      f"({', '.join(missing)}) {'are' if len(missing) > 1 else 'is'} not in the local "
                                      f"hash index (as of {as_of}); an online lookup can tell whether "
                                      f"{'they are' if len(missing) > 1 else 'it is'} published"}
        block["caveats"].append(caveat("local-version-list", as_of=as_of))
    return block


def relocated(ecosystem: str, version: str, block: dict, old: _Advisories, new_name: str, records: list[dict],
              listing: Listing, moved_by: str) -> dict | None:
    """Advice at the coordinates a POM relocates the package to (mysql:mysql-connector-java ->
    com.mysql:mysql-connector-j), when a release there leaves out more advisories than any release of the old
    coordinates. A finding the new coordinates have no advisory for is read from the old one's ranges."""
    if not listing.versions:
        return None
    new = _Advisories(ecosystem, new_name, version, records)
    current = old.hits(version)
    severity_of = {**new.severity_of, **old.severity_of}

    def hits(candidate):
        carried = {k for k in current if (k in new.matched(candidate) if k in new.by_key else k in old.hits(candidate))}
        return frozenset(carried) | (new.matched(candidate) - current)

    order = functools.cmp_to_key(lambda a, b: compare(ecosystem, a, b))
    pool = sorted((v for v in set(listing.versions) - listing.deprecated
                   if compare(ecosystem, v, version) > 0 and not prerelease(ecosystem, v)), key=order)
    found = _best(pool, hits, severity_of)
    staying = _weight(block["remaining"] if block.get("target") else current, severity_of)
    if not found or not found[1] < staying:
        return None
    target = found[0]
    ordered = functools.partial(sorted, key=lambda k: (vulns.SEVERITIES.index(severity_of.get(k, "UNKNOWN")), k))
    at = hits(target)
    caveats = [c for c in block["caveats"] if c["code"] not in ("compatibility-not-assessed", "flavor-choice",
                                                                 "flavor-dropped", "prerelease-only")]
    caveats.append(caveat("relocated", package=new_name, moved_by=moved_by))
    if line_of(ecosystem, target) != line_of(ecosystem, version):
        caveats.append(caveat("compatibility-not-assessed"))
    return {**{k: v for k, v in block.items() if k not in ("same_line", "alternatives", "osv_fixed")},
            "verdict": "relocated", "target": target, "target_package": new_name,
            "clears": ordered(current - at), "remaining": ordered(current & at), "introduced": ordered(at - current),
            "caveats": caveats, "versions_source": listing.source,
            "same_coordinates": {k: block.get(k) for k in ("verdict", "target", "clears", "remaining", "introduced")}}


def family_advice(ecosystem: str, group: str, version: str, members: list[tuple[str, _Advisories, Listing]],
                  own_targets: dict[str, str | None]) -> dict:
    """One target for a release family: the artifacts of one group at one version (spring-core, spring-web
    and spring-beans 5.3.4) are released together and move together. The target is a version every member
    is published at; it is weighed by the advisories of all of them, members without findings included."""
    block = {"family": f"{group}@{version}", "group": group, "version": version,
             "members": [purl for purl, _, _ in members], "verdict": None, "target": None,
             "clears": [], "remaining": [], "introduced": [], "caveats": []}
    severity_of = {}
    for _, package, _ in members:
        severity_of.update(package.severity_of)
    ordered = functools.partial(sorted, key=lambda k: (vulns.SEVERITIES.index(severity_of.get(k, "UNKNOWN")), k))

    def hits(candidate):
        return frozenset().union(*(package.hits(candidate) for _, package, _ in members))

    current = hits(version)
    block["remaining"] = ordered(current)
    missing = [purl for purl, _, listing in members if listing.versions is None]
    if missing:
        return block | {"verdict": "unverified",
                        "reason": "no version list for " + ", ".join(missing)}
    order = functools.cmp_to_key(lambda a, b: compare(ecosystem, a, b))
    lists = [set(listing.versions) - listing.deprecated for _, _, listing in members]
    common = set.intersection(*lists)
    own_variant = variant(ecosystem, version)
    on_prerelease = prerelease(ecosystem, version)
    pool = sorted((v for v in common if compare(ecosystem, v, version) > 0
                   and variant(ecosystem, v) in (None, own_variant)
                   and (on_prerelease or not prerelease(ecosystem, v))), key=order)
    verdict, target, same_line = _choose(ecosystem, version, pool, hits, severity_of)
    block.update(verdict=verdict, target=target)
    if target:
        at = hits(target)
        block.update(clears=ordered(current - at), remaining=ordered(current & at), introduced=ordered(at - current))
    block["per_member"] = [
        {"component": purl, "own_target": own_targets.get(purl),
         "remaining": ordered(package.hits(version) & package.hits(target)) if target else ordered(package.hits(version)),
         "introduced": ordered(package.hits(target) - package.hits(version)) if target else []}
        for purl, package, _ in members]
    if verdict == "upgrade-across-major":
        block["caveats"].append(caveat("compatibility-not-assessed"))
        if same_line and same_line[1] < _weight(current, severity_of):
            at = hits(same_line[0])
            block["same_line"] = {"target": same_line[0], "clears": ordered(current - at),
                                  "remaining": ordered(current & at), "introduced": ordered(at - current)}
    if verdict != "upgrade":
        last = {purl: max([v for v in listing.versions if not prerelease(ecosystem, v)] or listing.versions, key=order)
                for purl, _, listing in members}
        latest = max(last.values(), key=order)
        ended = [purl for purl, v in last.items() if compare(ecosystem, v, latest) < 0]
        if ended:
            block["caveats"].append(caveat("family-ends", members=", ".join(ended), latest=latest))
    as_of = next((listing.source.get("as_of") for _, _, listing in members if listing.source.get("as_of")), None)
    if as_of:
        block["caveats"].append(caveat("local-version-list", as_of=as_of))
    return block


def context_caveats(item: dict, table: dict) -> list[dict]:
    """Caveats that come from where and how the component was found rather than from its advisories."""
    out = []
    embedded = bool(item["contained_in"]) and not item["files"]
    if embedded:
        out.append(caveat("embedded-in-host", hosts=", ".join(item["contained_in"])))
    if any(f["published"] == "differs" for f in item["files"]):
        out.append(caveat("modified-jar"))
    if item["confidence"] == "declared" and not embedded:
        out.append(caveat("coordinates-unverified"))
    if item.get("scope") == "dev":
        out.append(caveat("dev-dependency"))
    vias = sorted({table[k]["affects"][item["purl"]]["via"] for k in item["vulnerabilities"]
                   if table[k]["affects"].get(item["purl"], {}).get("via")})
    if vias:
        out.append(caveat("via-alias", via=", ".join(vias)))
    return out


def alias_findings(item: dict, table: dict) -> list[dict]:
    out = []
    for key in item["vulnerabilities"]:
        affected = table[key]["affects"].get(item["purl"], {})
        if affected.get("via"):
            out.append({"id": key, "via": affected["via"], "fixed": affected["fixed"]})
    return out


def package_records(net: Net, db, ecosystem: str, name: str) -> list[dict]:
    """Every OSV record that names the package, whichever versions it covers."""
    if db is not None and db.has(OSV_DATASET[ecosystem]):
        return db.osv_records(ecosystem, name)
    body = {"package": {"name": name, "ecosystem": vulns.OSV_ECOSYSTEM[ecosystem]}}
    page = net.post_json(f"{vulns.OSV}/query", body) or {}
    records = list(page.get("vulns", []))
    while page.get("next_page_token"):
        page = net.post_json(f"{vulns.OSV}/query", body | {"page_token": page["next_page_token"]}) or {}
        records += page.get("vulns", [])
    return [r for r in records if not r.get("withdrawn")]


def _maven_metadata(net: Net, group: str, artifact: str, repositories: tuple[str, ...]) -> tuple[list[str], list[str]]:
    versions, answered = [], []
    for repository in (CENTRAL, *repositories):
        body = net.get(f"{repository}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml")
        if body is None:
            continue
        answered.append(repository)
        block = re.search(rb"<versions>(.*?)</versions>", body, re.S)
        versions += [v.decode("utf-8", "replace").strip()
                     for v in re.findall(rb"<version>([^<]+)</version>", block.group(1) if block else b"")]
    return list(dict.fromkeys(versions)), answered


def published_versions(net: Net, db, ecosystem: str, name: str, repositories: tuple[str, ...] = (),
                       expected: tuple[str, ...] = ()) -> Listing:
    """``expected``: versions the advisories call fixed. The local hash index answers when it has them all;
    otherwise the registry is asked, because the index trails it by up to a few weeks."""
    if ecosystem == "npm":
        try:
            document = net.get_json(f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}",
                                    headers={"Accept": NPM_ABBREVIATED})
        except OfflineMiss:
            return Listing(None, error="the npm registry's version list is not in the cache (offline)")
        except NetError as error:
            return Listing(None, error=f"npm registry: {error}")
        if document is None:
            return Listing(None, error="not in the npm registry")
        entries = document.get("versions") or {}
        return Listing(list(entries), frozenset(v for v, meta in entries.items() if (meta or {}).get("deprecated")),
                       {"source": "npm registry"})
    group, artifact = name.split(":", 1)
    local = None
    if db is not None and db.has("maven-hashes"):
        local = Listing(db.maven_versions(group, artifact),
                        source={"source": "local Maven Central hash index", "as_of": db.data_as_of("maven-hashes")})
        if local.versions and (net.offline or all(is_published("maven", f, local.versions) for f in expected)):
            return local
    try:
        versions, answered = _maven_metadata(net, group, artifact, repositories)
    except NetError as error:
        if local and local.versions:
            return local
        reason = ("not in the cache (offline)" if isinstance(error, OfflineMiss) else str(error))
        return Listing(None, error=f"maven-metadata.xml: {reason}")
    if not versions:
        if local and local.versions:
            return local
        return Listing(None, error="no repository publishes a version list (maven-metadata.xml) for it")
    merged = list(dict.fromkeys(versions + (local.versions if local and local.versions else [])))
    return Listing(merged, source={"source": "maven-metadata.xml", "repositories": answered})


RELOCATION = re.compile(rb"<relocation>(.*?)</relocation>", re.S)


def relocation(net: Net, name: str, version: str, repositories: tuple[str, ...] = ()) -> tuple[str, str] | None:
    """Where the POM of ``version`` relocates a Maven artifact (``<distributionManagement><relocation>``):
    the new name and which POM says so."""
    group, artifact = name.split(":", 1)
    for repository in (CENTRAL, *repositories):
        try:
            body = net.get(f"{repository}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom",
                           stable=True)
        except NetError:
            continue
        if body is None:
            continue
        block = RELOCATION.search(re.sub(rb"<!--.*?-->", b"", body, flags=re.S))
        if not block:
            return None

        def value(tag: bytes) -> str | None:
            match = re.search(rb"<" + tag + rb">\s*([^<\s$]+)\s*</" + tag + rb">", block.group(1))
            return match.group(1).decode("utf-8", "replace") if match else None

        moved = f"{value(b'groupId') or group}:{value(b'artifactId') or artifact}"
        return (moved, f"the POM of {name} {version}") if moved != name else None
    return None


def note_license_changes(items: list[dict], families: list[dict], license_of, workers: int = 16) -> None:
    """A caveat on advice whose target declares a more restrictive license than the version in use, or one
    binwitness does not classify (org.elasticsearch:elasticsearch 7.9.3, Apache-2.0, to 7.17, Elastic-2.0 or
    SSPL-1.0). Both sides are read the same way, ``license_of(ecosystem, name, version)``, from the registry:
    a license found inside the jar can come from a bundled library and would compare unlike with unlike.
    Where either side cannot be read or classified, nothing is said."""
    by_purl = {item["purl"]: item for item in items}
    pairs: list[tuple[dict, dict, str, str]] = []
    for item in items:
        block = item.get("upgrade") or {}
        if block.get("target"):
            pairs.append((block, item, block.get("target_package") or item["name"], block["target"]))
    for block in families:
        for purl in block["members"] if block.get("target") else ():
            pairs.append((block, by_purl[purl], by_purl[purl]["name"], block["target"]))
    keys = list(dict.fromkeys(key for _, item, name, target in pairs
                              for key in ((item["ecosystem"], item["name"], item["version"]),
                                          (item["ecosystem"], name, target))))
    declared = dict(zip(keys, map_parallel(lambda key: license_of(*key), keys, max(workers, 4))))
    changed: dict[int, tuple[dict, list[dict]]] = {}
    for block, item, name, target in pairs:
        before = declared[(item["ecosystem"], item["name"], item["version"])]
        after = declared[(item["ecosystem"], name, target)]
        if not before or not after or before["family"] in (UNKNOWN, after["family"]) or (
                after["family"] != UNKNOWN and FAMILIES.index(after["family"]) > FAMILIES.index(before["family"])):
            continue
        changed.setdefault(id(block), (block, []))[1].append(
            {"package": name, "target": target, "declared": _declared_text(after), "family": after["family"],
             "in_use": f"{item['name']} {item['version']}" if name != item["name"] else item["version"],
             "in_use_declared": _declared_text(before), "in_use_family": before["family"]})
    for block, changes in changed.values():
        alike: dict[tuple, list[str]] = {}
        for change in changes:
            alike.setdefault(tuple(v for k, v in change.items() if k != "package"), []).append(change["package"])
        text = "; ".join(f"{', '.join(packages)} {target} {declared} ({family}) against {in_use} {in_use_declared} "
                         f"({in_use_family})"
                         for (target, declared, family, in_use, in_use_declared, in_use_family), packages
                         in alike.items())
        block["caveats"].append({**caveat("license-changes", changes=text), "changes": changes})


def _declared_text(found: dict) -> str:
    """Several declarations are alternatives, as the family is read."""
    return " or ".join(found.get("expressions") or found.get("names") or [])


def _own(item: dict, table: dict) -> dict:
    """Findings from the component's own advisories, not from another coordinate of the same file."""
    return {k: table[k] for k in item["vulnerabilities"] if not table[k]["affects"].get(item["purl"], {}).get("via")}


def _families(items: list[dict], table: dict) -> dict[tuple[str, str], list[dict]]:
    """Maven artifacts of one group at one version, when one of them has findings. A library shaded into a
    host changes with the host, so it is left out."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for item in items:
        if item["ecosystem"] != "maven" or (item["contained_in"] and not item["files"]):
            continue
        groups.setdefault((item["name"].split(":", 1)[0], item["version"]), []).append(item)
    return {key: members for key, members in groups.items()
            if len(members) > 1 and any(_own(m, table) for m in members)}


def attach(net: Net, db, items: list[dict], table: dict, repositories: tuple[str, ...] = (), workers: int = 16,
           warnings: list[str] | None = None, log=None, families: list[dict] | None = None) -> int:
    """Sets ``upgrade`` on every component with findings and ``upgrade_family`` on the members of a release
    family, whose advice is appended to ``families``; returns how many components could not be checked."""
    warnings = warnings if warnings is not None else []
    families = families if families is not None else []
    wanted = [item for item in items if item["vulnerabilities"]]
    grouped = _families(items, table)
    involved = wanted + [m for members in grouped.values() for m in members if not m["vulnerabilities"]]
    packages = sorted({(i["ecosystem"], i["name"]) for i in involved})
    lowest = {}
    for item in involved:
        key = (item["ecosystem"], item["name"])
        if key not in lowest or compare(key[0], item["version"], lowest[key]) < 0:
            lowest[key] = item["version"]

    def gather(package, floor=None):
        ecosystem, name = package
        try:
            records = package_records(net, db, ecosystem, name)
        except NetError as error:
            reason = "not in the cache (offline)" if isinstance(error, OfflineMiss) else str(error)
            return None, Listing(None, error=f"OSV advisories of the package: {reason}")
        floor = floor or lowest[package]
        expected = tuple(dict.fromkeys(
            f for r in records for f in vulns.fixed_versions(r, ecosystem, name) if compare(ecosystem, f, floor) > 0))
        return records, published_versions(net, db, ecosystem, name, repositories, expected)

    gathered = dict(zip(packages, map_parallel(gather, packages, max(workers, 4))))
    not_checked = 0
    for item in wanted:
        records, listing = gathered[(item["ecosystem"], item["name"])]
        own = _own(item, table)
        aliases = alias_findings(item, table)
        if records is None:
            block = {"verdict": "unverified", "target": None, "clears": [], "remaining": list(own), "introduced": [],
                     "caveats": [], "reason": listing.error}
        elif not own:
            block = {"verdict": "unverified", "target": None, "clears": [], "remaining": [], "introduced": [],
                     "caveats": [], "reason": "every finding comes from another coordinate of the same file"}
        else:
            block = advise(item["ecosystem"], item["name"], item["version"], records, listing, own)
        if block["verdict"] == "unverified" and own:
            not_checked += 1
            warnings.append(f"upgrade advice for {item['purl']}: {block.get('reason')}")
        if aliases:
            block["via_alias"] = aliases
        block["caveats"] = context_caveats(item, table) + block["caveats"]
        item["upgrade"] = block

    # A coordinate that stopped being published may live on under another name: its last POM says where.
    order = functools.cmp_to_key(lambda a, b: compare("maven", a, b))
    stuck = [item for item in wanted if item["ecosystem"] == "maven" and not net.offline
             and item["upgrade"]["verdict"] in ("partial", "no-published-fix", "upgrade-across-major")]

    def moved(item):
        records, listing = gathered[("maven", item["name"])]
        if not listing.versions:
            return None
        found = relocation(net, item["name"], max(listing.versions, key=order), repositories)
        return (found, gather(("maven", found[0]), item["version"])) if found else None

    for item, found in zip(stuck, map_parallel(moved, stuck, max(workers, 4))):
        if not found:
            continue
        (new_name, moved_by), (records, listing) = found
        if records is None:
            continue
        old = _Advisories("maven", item["name"], item["version"], gathered[("maven", item["name"])][0],
                          _own(item, table))
        block = relocated("maven", item["version"], item["upgrade"], old, new_name, records, listing, moved_by)
        if block:
            item["upgrade"] = block

    for (group, version), members in sorted(grouped.items()):
        if any((m.get("upgrade") or {}).get("verdict") == "remove-malicious" for m in members):
            continue
        entries = []
        for member in sorted(members, key=lambda m: m["purl"]):
            records, listing = gathered[(member["ecosystem"], member["name"])]
            package = _Advisories(member["ecosystem"], member["name"], version, records or [], _own(member, table))
            entries.append((member["purl"], package, listing))
        block = family_advice("maven", group, version, entries,
                              {m["purl"]: (m.get("upgrade") or {}).get("target") for m in members})
        families.append(block)
        for member in members:
            member["upgrade_family"] = block["family"]
    if log and wanted:
        counts = {v: sum(1 for i in wanted if i["upgrade"]["verdict"] == v) for v in VERDICTS}
        log("upgrade advice: " + ", ".join(f"{v} {n}" for v, n in counts.items() if n)
            + (f"; {len(families)} release famil{'y' if len(families) == 1 else 'ies'} to move together"
               if families else ""))
    return not_checked
