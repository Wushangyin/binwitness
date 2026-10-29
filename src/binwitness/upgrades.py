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
from binwitness.localdb import OSV_DATASET
from binwitness.maven import CENTRAL
from binwitness.net import Net, NetError, OfflineMiss, map_parallel
from binwitness.versions import compare, prerelease, variant, without_variant

NPM_REGISTRY = "https://registry.npmjs.org"
# The abbreviated document lists versions and deprecations without readmes: kilobytes instead of megabytes.
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"
VERDICTS = ("remove-malicious", "upgrade", "upgrade-across-major", "partial", "no-published-fix", "unverified")
VERDICT_TEXT = {
    "remove-malicious": "malicious package: remove it; no version of it is an upgrade",
    "upgrade": "a later release on the same line is outside every advisory of this package",
    "upgrade-across-major": "only a later major line leaves out more advisories; compatibility is not assessed",
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


def advise(ecosystem: str, name: str, version: str, records: list[dict], listing: Listing,
           reported: dict[str, dict] | None = None) -> dict:
    """The upgrade block for one component. ``records``: every OSV record of the package. ``reported``: the
    scan's findings for this version from the package's own advisories, id -> table entry."""
    reported = reported or {}
    by_key: dict[str, list[dict]] = {}
    for record in records:
        if not record.get("withdrawn"):
            by_key.setdefault(vulns.key_of(record), []).append(record)
    severity_of = {k: min((vulns.severity(r)[0] for r in rs), key=vulns.SEVERITIES.index) for k, rs in by_key.items()}
    severity_of.update({k: v["severity"] for k, v in reported.items() if k not in severity_of})

    @functools.cache
    def matched(candidate: str) -> frozenset:
        return frozenset(k for k, rs in by_key.items() if any(vulns.affects(r, ecosystem, name, candidate) for r in rs))

    # OSV's own matching named these for the version in use, but their ranges do not read that way here.
    # Counting them in every candidate keeps the advice from claiming a fix it cannot show.
    unread = frozenset(k for k in reported if k not in matched(version))

    def hits(candidate: str) -> frozenset:
        return matched(candidate) | unread

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

    def best(choices):
        found = None
        for candidate in choices:
            weight = _weight(hits(candidate), severity_of)
            if found is None or weight < found[1]:
                found = (candidate, weight)
                # Candidates come in ascending order: the first one outside every advisory is the nearest.
                if not any(weight):
                    break
        return found

    home = line_of(ecosystem, version)
    same_line = best([v for v in pool if line_of(ecosystem, v) == home])
    anywhere = best(pool)
    now = _weight(current, severity_of)
    if same_line and not any(same_line[1]):
        verdict, target = "upgrade", same_line[0]
    elif anywhere and anywhere[1] < (same_line[1] if same_line else now):
        verdict, target = "upgrade-across-major", anywhere[0]
    elif same_line and same_line[1] < now:
        verdict, target = "partial", same_line[0]
    else:
        verdict, target = "no-published-fix", None

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
        early = best([v for v in newer if fits(v) and prerelease(ecosystem, v)])
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


def attach(net: Net, db, items: list[dict], table: dict, repositories: tuple[str, ...] = (), workers: int = 16,
           warnings: list[str] | None = None, log=None) -> int:
    """Sets ``upgrade`` on every component with findings; returns how many could not be checked."""
    warnings = warnings if warnings is not None else []
    wanted = [item for item in items if item["vulnerabilities"]]
    packages = sorted({(i["ecosystem"], i["name"]) for i in wanted})
    lowest = {}
    for item in wanted:
        key = (item["ecosystem"], item["name"])
        if key not in lowest or compare(key[0], item["version"], lowest[key]) < 0:
            lowest[key] = item["version"]

    def gather(package):
        ecosystem, name = package
        try:
            records = package_records(net, db, ecosystem, name)
        except NetError as error:
            reason = "not in the cache (offline)" if isinstance(error, OfflineMiss) else str(error)
            return None, Listing(None, error=f"OSV advisories of the package: {reason}")
        expected = tuple(dict.fromkeys(
            f for r in records for f in vulns.fixed_versions(r, ecosystem, name)
            if compare(ecosystem, f, lowest[package]) > 0))
        return records, published_versions(net, db, ecosystem, name, repositories, expected)

    gathered = dict(zip(packages, map_parallel(gather, packages, max(workers, 4))))
    not_checked = 0
    for item in wanted:
        records, listing = gathered[(item["ecosystem"], item["name"])]
        own = {k: table[k] for k in item["vulnerabilities"]
               if not table[k]["affects"].get(item["purl"], {}).get("via")}
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
    if log and wanted:
        counts = {v: sum(1 for i in wanted if i["upgrade"]["verdict"] == v) for v in VERDICTS}
        log("upgrade advice: " + ", ".join(f"{v} {n}" for v, n in counts.items() if n))
    return not_checked
