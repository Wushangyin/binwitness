"""Result files: native JSON, CycloneDX 1.5 SBOM with vulnerabilities, CSV tables, terminal summary."""
from __future__ import annotations

import csv
import functools
import json
import uuid
from pathlib import Path

from binwitness import __version__
from binwitness.licenses import spdx_id
from binwitness.versions import compare
from binwitness.vulns import SEVERITIES

_TECHNIQUE = {"exact": ("hash-comparison", 1.0), "content": ("hash-comparison", 0.9),
              "declared": ("manifest-analysis", 0.7)}
_SCOPE = {"runtime": "required", "dev": "excluded"}


def write_all(result: dict, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = [out_dir / "binwitness.json", out_dir / "sbom.cdx.json", out_dir / "components.csv",
             out_dir / "vulnerabilities.csv"]
    paths[0].write_text(json.dumps(result, ensure_ascii=False, indent=1), "utf-8")
    paths[1].write_text(json.dumps(cyclonedx(result), ensure_ascii=False, indent=1), "utf-8")
    components_csv(result, paths[2])
    vulnerabilities_csv(result, paths[3])
    return paths


def cyclonedx(result: dict) -> dict:
    components = []
    refs: dict[str, list[str]] = {}
    for c in result["components"]:
        group, name = c["name"].split(":", 1) if c["ecosystem"] == "maven" else ("", c["name"])
        technique, confidence = _TECHNIQUE[c["confidence"]]
        entry = {"type": "library", "bom-ref": c["purl"], "name": name, "version": c["version"], "purl": c["purl"]}
        if group:
            entry["group"] = group
        if c["scope"] in _SCOPE:
            entry["scope"] = _SCOPE[c["scope"]]
        license_ = c.get("license") or {}
        if license_.get("expressions"):
            entry["licenses"] = [{"expression": e} for e in license_["expressions"]][:1]
        elif license_.get("names"):
            entry["licenses"] = _license_entries(license_["names"])
        entry["evidence"] = {
            "identity": {"field": "purl", "confidence": confidence,
                         "methods": [{"technique": _TECHNIQUE[e["confidence"]][0],
                                      "confidence": _TECHNIQUE[e["confidence"]][1], "value": e["method"]}
                                     for e in c["evidence"]]},
            "occurrences": [{"location": loc} for loc in c["locations"]],
        }
        properties = [{"name": "binwitness:also-published-as", "value": p}
                      for p in dict.fromkeys(p for f in c["files"] for p in f.get("also_published_as", []))]
        properties += [{"name": "binwitness:contained-in", "value": p} for p in c["contained_in"]]
        if c.get("upgrade"):
            properties.append({"name": "binwitness:upgrade", "value": upgrade_text(c["upgrade"])})
        if c.get("vulnerabilities_checked") is False:
            properties.append({"name": "binwitness:vulnerabilities", "value": "not checked: the lookup failed"})
        # One entry per file: a tampered copy and the original share coordinates but not hashes, and a
        # reviewer needs to know which of them was changed.
        for file in c["files"] or [None]:
            copy = dict(entry)
            if file:
                if len(c["files"]) > 1:
                    copy["bom-ref"] = f"{c['purl']}#{file['sha1']}"
                    copy["evidence"] = {**entry["evidence"],
                                        "occurrences": [{"location": loc} for loc in file["locations"]]}
                copy["hashes"] = _hashes(file)
                extra = [{"name": "binwitness:published", "value": file["published"]}]
                if file.get("repository"):
                    extra.append({"name": "binwitness:repository", "value": file["repository"]})
                copy["properties"] = extra + properties
            elif properties:
                copy["properties"] = properties
            refs.setdefault(c["purl"], []).append(copy["bom-ref"])
            components.append(copy)
    # A file the scan could not name is still part of what was delivered.
    for kind, entries in (("first-party", result["first_party"]), ("unidentified", result["unidentified"])):
        for jar in entries:
            entry = {"type": "file", "bom-ref": f"file:{jar['sha1']}", "name": jar["filename"],
                     "hashes": _hashes(jar), "evidence": {"occurrences": [{"location": loc}
                                                                          for loc in jar["locations"]]},
                     "properties": [{"name": "binwitness:status", "value": kind}]}
            if jar.get("coordinate"):
                entry["properties"].append({"name": "binwitness:declared-coordinate", "value": jar["coordinate"]})
            if jar.get("reason"):
                entry["properties"].append({"name": "binwitness:reason", "value": jar["reason"]})
            if jar.get("hint"):
                entry["properties"].append({"name": "binwitness:manifest-says", "value": jar["hint"]})
            if (jar.get("license") or {}).get("names"):
                entry["licenses"] = _license_entries(jar["license"]["names"])
            components.append(entry)
    vulnerabilities = []
    for v in result["vulnerabilities"].values():
        rating = {"severity": v["severity"].lower() if v["severity"] != "UNKNOWN" else "unknown"}
        if v["cvss_vector"] and v["cvss_vector"].startswith("CVSS:3"):
            rating.update(method="CVSSv31" if v["cvss_vector"].startswith("CVSS:3.1") else "CVSSv3",
                          vector=v["cvss_vector"])
            if v["cvss_score"] is not None:
                rating["score"] = v["cvss_score"]
        entry = {"bom-ref": f"vuln:{v['id']}", "id": v["id"],
                 "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v['osv_ids'][0]}"},
                 "ratings": [rating], "description": v["summary"],
                 "affects": [{"ref": ref} for purl in v["affects"] for ref in refs.get(purl, [purl])]}
        if v["published"]:
            entry["published"] = v["published"]
        if v["aliases"]:
            entry["references"] = [{"id": a, "source": {"name": "OSV",
                                                         "url": f"https://osv.dev/vulnerability/{a}"}}
                                   for a in v["aliases"]]
        if v["kev_date_added"]:
            entry["properties"] = [{"name": "binwitness:cisa-kev-date-added", "value": v["kev_date_added"]}]
        vulnerabilities.append(entry)
    metadata = {"timestamp": result["finished"],
                "tools": {"components": [{"type": "application", "name": "binwitness", "version": __version__}]}}
    subjects = [_subject(i) for i in result["inputs"]]
    # bom-refs must be unique, and two inputs can share a name (release/app.jar and backup/app.jar).
    for number, subject in enumerate(subjects):
        if any(other["bom-ref"] == subject["bom-ref"] for other in subjects[:number]):
            subject["bom-ref"] += f"#{number + 1}"
    if len(subjects) == 1:
        metadata["component"] = subjects[0]
    elif subjects:
        metadata["component"] = {"type": "application", "bom-ref": "inputs",
                                 "name": ", ".join(s["name"] for s in subjects), "components": subjects}
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": metadata,
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def _hashes(file: dict) -> list[dict]:
    return [{"alg": "SHA-1", "content": file["sha1"]}] + (
        [{"alg": "SHA-256", "content": file["sha256"]}] if file.get("sha256") else [])


def _license_entries(names: list[str]) -> list[dict]:
    """SPDX ids where the name has one: policy tools match licenses by id, not by name."""
    entries = []
    for name in names:
        entry = {"id": spdx_id(name)} if spdx_id(name) else {"name": name}
        if {"license": entry} not in entries:
            entries.append({"license": entry})
    return entries


def _subject(described: dict) -> dict:
    entry = {"type": "application", "bom-ref": f"input:{described['name']}", "name": described["name"]}
    if described.get("sha256"):
        entry["hashes"] = [{"alg": "SHA-256", "content": described["sha256"]}]
    return entry


def _counts(component: dict, table: dict) -> list[int]:
    levels = [table[k]["severity"] for k in component["vulnerabilities"]]
    return [levels.count(s) for s in SEVERITIES]


def components_csv(result: dict, path: Path):
    table = result["vulnerabilities"]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        # The byte order mark tells Excel the encoding; without it, non-ASCII paths come out garbled.
        writer = csv.writer(handle)
        writer.writerow(["ecosystem", "name", "version", "purl", "scope", "confidence", "identified by",
                         "published artifact", "also published as", "contained in", "license family", "licenses",
                         *[s.lower() for s in SEVERITIES], "vulnerabilities", "occurrences", "first location",
                         "upgrade"])
        for c in result["components"]:
            license_ = c.get("license") or {}
            writer.writerow([
                c["ecosystem"], c["name"], c["version"], c["purl"], c["scope"], c["confidence"],
                "; ".join(e["method"] for e in c["evidence"]),
                "; ".join(sorted({f["published"] + (f" ({f['repository']})" if f.get("repository") else "")
                                  for f in c["files"]})),
                "; ".join(dict.fromkeys(p for f in c["files"] for p in f.get("also_published_as", []))),
                "; ".join(c["contained_in"]),
                license_.get("family", ""), "; ".join(license_.get("expressions") or license_.get("names") or []),
                *_counts(c, table),
                " ".join(c["vulnerabilities"] + (["(lookup incomplete)"] if c.get("vulnerabilities_checked") is False
                                                 else [])),
                len(c["locations"]), c["locations"][0], upgrade_text(c["upgrade"]) if c.get("upgrade") else ""])


def vulnerabilities_csv(result: dict, path: Path):
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "aliases", "severity", "severity source", "cvss score", "cvss vector",
                         "known exploited (CISA KEV)", "malicious package", "published", "affects", "summary"])
        for v in result["vulnerabilities"].values():
            affects = "; ".join(f"{ref} (fixed: {', '.join(x['fixed']) or 'none listed'}"
                                + (f"; advisory names {x['via']})" if x.get("via") else ")")
                                for ref, x in v["affects"].items())
            writer.writerow([v["id"], " ".join(v["aliases"]), v["severity"], v["severity_source"], v["cvss_score"],
                             v["cvss_vector"], v["kev_date_added"] or "", "yes" if v["malicious"] else "",
                             v["published"], affects, v["summary"]])


def render_summary(result: dict) -> str:
    s, options = result["summary"], result["options"]
    c, j, v = s["components"], s["jars"], s["vulnerabilities"]
    lines = [f"components   {c['total']}" + (
        f"  ({_listing(sorted(c['by_ecosystem'].items()))}; "
        f"{_listing((k, c['by_confidence'].get(k, 0)) for k in ('exact', 'content', 'declared'))})"
        if c["total"] else "")]
    lines.append(f"jars         {j['distinct_files']} distinct" + (
        ": " + _listing([("third-party", j["third_party"]), ("first-party", j["first_party"]),
                         ("inside identified libraries", j.get("inside_identified_libraries", 0)),
                         ("unidentified", j["unidentified"])]) if j["distinct_files"] else "")
        + (f"; {j['skipped_java_runtime']} Java runtime jars skipped" if j.get("skipped_java_runtime") else ""))
    if j["differ_from_published"] or j["not_on_central"] or j["repackaged"]:
        lines.append(f"             {j['differ_from_published']} differ from the published artifact, "
                     f"{j['repackaged']} repackaged with unchanged contents"
                     + (f" ({j['copies_of_identified_jars']} by the entries of another jar in the delivery)"
                        if j.get("copies_of_identified_jars") else "")
                     + f", {j['not_on_central']} declare coordinates not published on Maven Central"
                     + (" or the --maven-repo repositories" if options.get("maven_repos") else ""))
    if not options.get("vulnerabilities", True):
        lines.append("vulns        not looked up (--no-vulns)")
    else:
        lines.append(f"vulns        {v['total']} distinct" + (": " + _listing(
            [(k.lower(), n) for k, n in v["by_severity"].items()]
            + [("known exploited", v["known_exploited"]), ("MALICIOUS", v["malicious_packages"])])
            if v["total"] else ""))
        lines += _worst(result)
        advice = (s.get("upgrades") or {})
        if options.get("upgrades") and advice.get("by_verdict"):
            unpublished = advice.get("fix_versions_not_published")
            lines.append("upgrades     " + _listing((_VERDICT_LABEL[k], n) for k, n in advice["by_verdict"].items())
                         + (f"; {unpublished} advisor{'y names' if unpublished == 1 else 'ies name'} a fixed version "
                            "that is not published" if unpublished else ""))
    if not options.get("licenses", True):
        lines.append("licenses     not looked up (--no-licenses)")
    elif c["total"]:
        lines.append("licenses     " + _listing(sorted(s["licenses"]["by_family"].items())))
    incomplete = s.get("incomplete") or {}
    if incomplete:
        lines.append("INCOMPLETE   " + "; ".join(INCOMPLETE[k].format(n=n) for k, n in incomplete.items())
                     + " (see warnings)")
    unnamed = [u for u in result["unidentified"] if u["reason"].startswith("no registry has this file")]
    if unnamed and not (options.get("class_search") and options.get("maven_repos")):
        lines.append(f"tip          {len(unnamed)} unidentified jar{'' if len(unnamed) == 1 else 's'}: "
                     + " ".join(x for x in (
                         "--class-search compares rebuilt jars with Maven Central by content;"
                         if not options.get("class_search") else "",
                         "--maven-repo URL also checks another repository (milestones, a vendor's own)"
                         if not options.get("maven_repos") else "") if x).rstrip(";"))
    if result["warnings"]:
        lines.append(f"warnings     {len(result['warnings'])} (see binwitness.json)")
    return "\n".join(lines)


INCOMPLETE = {
    "jars_not_looked_up": "{n} jars not looked up",
    "scripts_not_looked_up": "{n} scripts not looked up",
    "jar_files_not_compared": "{n} jars not compared with the published artifact",
    "vulnerabilities_not_checked": "vulnerabilities not checked for {n} components",
    "licenses_not_looked_up": "licenses not looked up for {n} components",
    "kev_catalog_unavailable": "CISA KEV catalog unavailable",
    "upgrade_versions_not_checked": "upgrade targets not checked for {n} components",
}
_VERDICT_LABEL = {"remove-malicious": "remove (malicious)", "upgrade": "upgrade on the same line",
                  "upgrade-across-major": "only across a major version", "partial": "partial",
                  "no-published-fix": "no published fix", "unverified": "not checked"}
# The summary names this many of the worst findings; the CSV and JSON have all of them.
WORST_SHOWN = 10


def _listing(pairs) -> str:
    return ", ".join(f"{k} {n}" for k, n in pairs if n) or "none"


def worst_findings(result: dict) -> list[dict]:
    """Malicious packages, known-exploited and critical or high findings, worst first."""
    worst = [x for x in result["vulnerabilities"].values()
             if x["malicious"] or x["kev_date_added"] or x["severity"] in ("CRITICAL", "HIGH")]
    worst.sort(key=lambda x: (not x["malicious"], not x["kev_date_added"], SEVERITIES.index(x["severity"]), x["id"]))
    return worst


def _worst(result: dict) -> list[str]:
    """The worst findings, each with what it affects."""
    named = {c["purl"]: c for c in result["components"]}
    worst = worst_findings(result)
    lines = []
    for x in worst[:WORST_SHOWN]:
        ref, affected = next(iter(x["affects"].items()))
        component = named.get(ref)
        label = f"{component['name']} {component['version']}" if component else ref
        more = f" and {len(x['affects']) - 1} more" if len(x["affects"]) > 1 else ""
        fixed = finding_advice(component, x["id"], affected) if component else ""
        flags = "".join((" MALICIOUS" if x["malicious"] else "", " KEV" if x["kev_date_added"] else ""))
        lines.append(f"  {x['severity'].lower():8} {x['id']:20} {label}{more}{fixed}{flags}")
    if len(worst) > WORST_SHOWN:
        lines.append(f"  ... {len(worst) - WORST_SHOWN} more (vulnerabilities.csv)")
    return lines


def _next_fixed(component: dict, fixed: list[str]) -> str | None:
    """The first fixed release after the version in use: advisories list a fix per release line, and the
    fix on an older line (5.7.13 for a 6.1.5) is no upgrade path."""
    later = [f for f in fixed if compare(component["ecosystem"], f, component["version"]) > 0]
    return min(later, key=functools.cmp_to_key(lambda a, b: compare(component["ecosystem"], a, b)), default=None)


def upgrade_text(upgrade: dict) -> str:
    text = upgrade["verdict"] + (f" {upgrade['target']}" if upgrade.get("target") else "")
    if upgrade.get("target") and upgrade["remaining"]:
        text += f" ({len(upgrade['remaining'])} remain)"
    return text


def finding_advice(component: dict, key: str, affected: dict) -> str:
    """What to do about one finding: the component's upgrade advice when it speaks to this finding, else the
    advisory's own fixed version."""
    upgrade = component.get("upgrade")
    target = upgrade and upgrade.get("target")
    if upgrade and upgrade["verdict"] == "remove-malicious":
        return ", remove it"
    if target and key in upgrade["clears"]:
        return f", upgrade to {target}" + (" (next major)" if upgrade["verdict"] == "upgrade-across-major" else "")
    if upgrade and upgrade["verdict"] == "no-published-fix" and key in upgrade["remaining"]:
        return ", no published fix"
    if target and key in upgrade["remaining"]:
        return f", not fixed in {target} either"
    later = _next_fixed(component, affected["fixed"])
    if not later:
        return ""
    # Without a version list the advisory's number is all there is, and it may never have been published.
    return f", fixed in {later}" + (" (not checked against the registry)" if upgrade or affected.get("via") else "")
