"""Result files: native JSON, CycloneDX 1.5 SBOM with vulnerabilities, CSV tables, terminal summary."""
from __future__ import annotations

import csv
import functools
import json
import uuid
from collections import Counter
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
             out_dir / "vulnerabilities.csv", out_dir / "candidates.csv"]
    paths[0].write_text(json.dumps(result, ensure_ascii=False, indent=1), "utf-8")
    paths[1].write_text(json.dumps(cyclonedx(result), ensure_ascii=False, indent=1), "utf-8")
    components_csv(result, paths[2])
    vulnerabilities_csv(result, paths[3])
    candidates_csv(result, paths[4])
    return paths


def cyclonedx(result: dict) -> dict:
    components = []
    refs: dict[str, list[str]] = {}
    families = families_of(result)
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
        if c.get("upgrade_family") in families:
            properties.append({"name": "binwitness:upgrade-family",
                               "value": family_text(families[c["upgrade_family"]])})
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
                         "upgrade", "upgrade family"])
        families = families_of(result)
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
                len(c["locations"]), c["locations"][0], _upgrade_cell(c, families.get(c.get("upgrade_family"))),
                family_text(families[c["upgrade_family"]]) if c.get("upgrade_family") in families else ""])


def _upgrade_cell(component: dict, family: dict | None) -> str:
    """A family member moves with its family: the family's advice comes first, so that a reader of this
    column alone does not upgrade spring-web and spring-core to different versions."""
    own = upgrade_text(component["upgrade"]) if component.get("upgrade") else ""
    if not family:
        return own
    text = family["verdict"]
    if family.get("target"):
        text += f" {family['target']}" + (f" ({len(family['remaining'])} remain)" if family["remaining"] else "")
    text += " with its family"
    return text + (f" (alone: {own})" if own else "")


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


CANDIDATE_COLUMNS = ["id", "severity", "cvss score", "cvss vector", "cvss source", "nvd status", "disputed",
                     "known exploited (CISA KEV)", "published", "component", "cpe", "affected versions",
                     "versions from", "only on a line below those listed", "product in the CNA's record", "cna",
                     "cna published", "only together with another product", "learned link (package / product / project)",
                     "link learned from", "link rests on one CVE", "packages linked with this cpe", "reached by",
                     "modules the vendor's advisory names", "advisory names another module",
                     "same flaw as finding", "names only another language", "named classes in this jar",
                     "named classes not in this jar", "classes the fix changed", "of them in this jar",
                     "none of the fix's classes in this jar", "fix commits", "cwe", "description", "url", "data as of"]
REACHED_BY = {"learned": "learned link", "named": "named in the record", "advisory": "named in the vendor's advisory",
              "cna_package": "package named in the CNA's record", "cna_cpe": "CPE in the CNA's record",
              "cna_learned": "learned link (product in the CNA's record)",
              "advisory_direct": "module named in the vendor's advisory, with its versions"}
VERSIONS_FROM = {"nvd": "NVD", "cna": "CNA's record", "advisory": "vendor's advisory"}


def candidates_csv(result: dict, path: Path):
    """One row per candidate and component. Written also when candidates were not looked for, with that
    said in it: an empty table would read as "none found"."""
    summary = (result.get("summary") or {}).get("candidates") or {}
    links = result.get("candidate_links") or {}
    dates = "; ".join(f"{name} {stamp[:10]}" for name, stamp in (summary.get("data_as_of") or {}).items() if stamp)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(CANDIDATE_COLUMNS)
        if not summary.get("checked"):
            pad = CANDIDATE_COLUMNS.index("description") - 1
            writer.writerow(["not checked", *[""] * pad, summary.get("not_checked") or "candidates were not looked for",
                             "", dates])
            return
        rows = []
        for c in (result.get("candidates") or {}).values():
            for ref, a in c["affects"].items():
                link = (links.get(ref) or {}).get(a["cpe"]) or {}
                rows.append([c["id"], c["severity"], c["cvss_score"], c["cvss_vector"], c["cvss_source"], c["status"],
                             "yes" if c["disputed"] else "", c["kev_date_added"] or "", (c["published"] or "")[:10],
                             ref, a["cpe"], a["versions"], VERSIONS_FROM.get(a.get("versions_from", "nvd"), ""),
                             "yes" if a.get("below_listed_lines") else "", a.get("cna_product") or "",
                             c.get("cna") or "", (c.get("cna_published") or "")[:10],
                             "yes" if a["conditional"] else "", _link_text(link),
                             " ".join(link.get("learned_from") or []), "yes" if a["single_cve_link"] else "",
                             link.get("packages", ""), REACHED_BY.get(a.get("basis", "learned"), ""),
                             " ".join(c.get("advisory_modules") or []),
                             "yes" if a.get("advisory_names_another_module") else "",
                             " ".join(a.get("related_findings") or []), "yes" if a.get("other_language_only") else "",
                             _classes_text(a.get("classes_in_jar"), c), _classes_text(a.get("classes_not_in_jar"), c),
                             " ".join(c.get("fixed_classes") or []), _fixed_text(a.get("fixed_classes_in_jar", []), c),
                             "yes" if a.get("fixed_classes_not_in_jar") else "",
                             " ".join(f["url"] for f in c.get("fix_commits") or []),
                             " ".join(c["cwe"]), c["description"], c["url"], dates])
        rows.sort(key=lambda r: (SEVERITIES.index(r[1]), r[0], r[9]))
        writer.writerows(rows)


def _link_text(link: dict) -> str:
    if not link:
        return ""
    text = (f"{link['shared']}/{link['package_cves']} / {link['product_same_project']}/{link['product_attributed']}"
            f" / {link['project_shared']}/{link['project_cves']}")
    if "ranges_meet" in link:
        text += f"; versions meet on {link['ranges_meet']} of {link['ranges_meet'] + link['ranges_apart']}"
    return text


def _classes_text(names: list[str] | None, candidate: dict) -> str:
    if names is None:
        return "jar contents unknown" if candidate.get("classes_named") else ""
    return " ".join(names)


def _fixed_text(names: list[str] | None, candidate: dict) -> str:
    if names is None:
        return "jar contents unknown" if candidate.get("fixed_classes") else ""
    return " ".join(names)


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
    scripts = s.get("scripts") or {}
    if any(scripts.values()):
        lines.append("scripts      " + _listing([("matched", scripts["matched"]),
                                                  ("version not determined", scripts["version_not_determined"]),
                                                  ("bundles", scripts["bundles"]), ("unmatched", scripts["unmatched"]),
                                                  ("project files not looked up",
                                                   scripts["project_files_not_looked_up"])]))
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
            together = advice.get("families")
            lines.append("upgrades     " + _listing((_VERDICT_LABEL[k], n) for k, n in advice["by_verdict"].items())
                         + (f"; {unpublished} advisor{'y names' if unpublished == 1 else 'ies name'} a fixed version "
                            "that is not published" if unpublished else "")
                         + (f"; {together} release famil{'y' if together == 1 else 'ies'} (artifacts of one group "
                            "and version) with one target each" if together else ""))
        lines += _candidate_lines(s.get("candidates"))
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


def _candidate_lines(summary: dict | None) -> list[str]:
    if summary is None:  # a result from before 0.4.0
        return []
    if not summary.get("checked"):
        return [f"candidates   not checked: {summary.get('not_checked')}"]
    counts = summary["components"]
    dates = ", ".join(f"{name} of {stamp[:10]}" for name, stamp in summary.get("data_as_of", {}).items() if stamp)
    from_cna = summary.get("records_from_cna", 0)
    lines = [f"candidates   {summary['total']} CVE records not attributed to a package in the local OSV data"
             + (f" ({from_cna} of them as their CNAs published them: NVD has given no CPE yet)" if from_cna else "")
             + ", not counted above; leads for manual review" + (": " + _listing(
                 [(k.lower(), n) for k, n in summary["by_severity"].items()]
                 + [("disputed", summary["disputed"]), ("known exploited", summary["known_exploited"]),
                    ("only from links that rest on one CVE", summary["only_from_single_cve_links"])])
                 if summary["total"] else "") + " (candidates.csv)",
             f"             looked for in {counts['with_link']} components whose CPE could be learned; "
             f"{counts['without_link']} without one were not checked"
             + (f", nor {counts['not_checked']} more: " + "; ".join(summary.get("components_not_checked_because", {}))
                if counts["not_checked"] else "")
             + (f"; NVD has given no CPE yet to {sum(summary['nvd_records_without_cpe'].values()):,} records"
                if summary.get("nvd_records_without_cpe") else "")
             + (f" (local {dates})" if dates else "")]
    flagged, left_out = summary.get("pairs_flagged"), summary.get("pairs_left_out") or {}
    refused = sum((summary.get("links_refused") or {}).values())
    if flagged is not None:
        lines.append(f"             {summary['pairs']} component pairs, flagged for review: " + _listing(
            [("same flaw as a finding", flagged["same_flaw_as_a_finding"]),
             ("record names only another language", flagged["other_language_only"]),
             ("named classes not in the jar", flagged["named_classes_not_in_jar"]),
             ("the vendor's advisory names another module", flagged.get("advisory_names_another_module", 0)),
             ("none of the classes its fix changed in the jar", flagged.get("fixed_classes_not_in_jar", 0)),
             ("only on a line below those the vendor lists", flagged.get("below_listed_lines", 0))])
            + (f"; {summary['pairs_reached_by_advisory']} pairs reached through the vendor's advisory"
               if summary.get("pairs_reached_by_advisory") else "")
            + ("; pairs left out: " + _listing([(LEFT_OUT.get(k, k), n) for k, n in sorted(left_out.items())])
               if sum(left_out.values()) else "")
            + (f"; {refused} CPE links refused: NVD's versions never meet OSV's" if refused else ""))
    fixes = summary.get("fix_commits")
    if fixes and fixes["candidates_citing_a_commit"]:
        read = fixes["commits"]
        lines.append(f"             fixes: {fixes['candidates_with_fixed_classes']} of the "
                     f"{fixes['candidates_citing_a_commit']} candidates citing a GitHub commit have the classes it "
                     "changed; commits " + _listing(
                         [("read", read.get("main classes", 0)),
                          ("without main-code classes", read.get("no main-code class", 0)),
                          ("too large to read", read.get("too large", 0)), ("not found", read.get("not found", 0)),
                          ("not read yet (sync fixes again)", read.get("not read", 0))])
                     + (f", {fixes['commits_elsewhere']} of other projects not used" if fixes["commits_elsewhere"]
                        else ""))
    return lines


LEFT_OUT = {"names_another_module": "the record names another module",
            "package_name_narrows": "the CNA's package name leaves the build out",
            "versions_not_told": "the CNA's record does not tell whether the version is affected"}
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
                  "upgrade-across-major": "only across a major version", "relocated": "at new coordinates",
                  "partial": "partial",
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
    """The worst findings, each with what it affects; how many others there are, so that the counts add up."""
    named = {c["purl"]: c for c in result["components"]}
    families = families_of(result)
    worst = worst_findings(result)
    lines = []
    for x in worst[:WORST_SHOWN]:
        ref, affected = next(iter(x["affects"].items()))
        component = named.get(ref)
        label = f"{component['name']} {component['version']}" if component else ref
        more = f" and {len(x['affects']) - 1} more" if len(x["affects"]) > 1 else ""
        fixed = finding_advice(component, x["id"], affected, families.get(component.get("upgrade_family"))) \
            if component else ""
        flags = "".join((" MALICIOUS" if x["malicious"] else "", " KEV" if x["kev_date_added"] else ""))
        lines.append(f"  {x['severity'].lower():8} {x['id']:20} {label}{more}{fixed}{flags}")
    listed = {x["id"] for x in worst}
    rest = Counter(x["severity"] for x in result["vulnerabilities"].values() if x["id"] not in listed)
    rest_text = _listing((s.lower(), rest[s]) for s in SEVERITIES if rest[s])
    hidden = len(worst) - WORST_SHOWN
    if hidden > 0 or rest:
        lines.append("  ... " + ", and ".join(part for part in (
            f"{hidden} more" if hidden > 0 else "", f"{rest_text} not listed here" if rest else "") if part)
            + " (vulnerabilities.csv)")
    return lines


def families_of(result: dict) -> dict[str, dict]:
    return {f["family"]: f for f in result.get("upgrade_families") or []}


def target_text(upgrade: dict) -> str:
    """The target, and the variant builds that do equally well (33.7.2-android or 33.7.2-jre)."""
    return " or ".join([upgrade["target"], *upgrade.get("alternatives", [])])


def _next_fixed(component: dict, fixed: list[str]) -> str | None:
    """The first fixed release after the version in use: advisories list a fix per release line, and the
    fix on an older line (5.7.13 for a 6.1.5) is no upgrade path."""
    later = [f for f in fixed if compare(component["ecosystem"], f, component["version"]) > 0]
    return min(later, key=functools.cmp_to_key(lambda a, b: compare(component["ecosystem"], a, b)), default=None)


def upgrade_text(upgrade: dict) -> str:
    text = upgrade["verdict"]
    if upgrade.get("target"):
        text += f" {upgrade['target_package']} {upgrade['target']}" if upgrade.get("target_package") \
            else f" {target_text(upgrade)}"
        if upgrade["remaining"]:
            text += f" ({len(upgrade['remaining'])} remain)"
    return text


def family_text(family: dict) -> str:
    """org.springframework@5.3.4 (9 artifacts): upgrade-across-major 6.2.19"""
    text = f"{family['family']} ({len(family['members'])} artifacts): {family['verdict']}"
    if family.get("target"):
        text += f" {family['target']}" + (f" ({len(family['remaining'])} remain)" if family["remaining"] else "")
    return text


def finding_advice(component: dict, key: str, affected: dict, family: dict | None = None) -> str:
    """What to do about one finding: the advice for the component's release family or for the component
    itself when it speaks to this finding, else the advisory's own fixed version."""
    upgrade = component.get("upgrade")
    target = upgrade and upgrade.get("target")
    if upgrade and upgrade["verdict"] == "remove-malicious":
        return ", remove it"
    if family and family.get("target") and key in family["clears"]:
        others = len(family["members"]) - 1
        return (f", upgrade to {family['target']} with the other {others} {family['group']} "
                f"artifact{'' if others == 1 else 's'}"
                + (" (next major)" if family["verdict"] == "upgrade-across-major" else ""))
    if target and upgrade.get("target_package") and key in upgrade["clears"]:
        return f", move to {upgrade['target_package']} {target}"
    if target and key in upgrade["clears"]:
        return f", upgrade to {target_text(upgrade)}" + (
            " (next major)" if upgrade["verdict"] == "upgrade-across-major" else "")
    if upgrade and upgrade["verdict"] == "no-published-fix" and key in upgrade["remaining"]:
        return ", no published fix"
    if target and key in upgrade["remaining"]:
        return f", not fixed in {target} either"
    later = _next_fixed(component, affected["fixed"])
    if not later:
        return ""
    # Without a version list the advisory's number is all there is, and it may never have been published.
    return f", fixed in {later}" + (" (not checked against the registry)" if upgrade or affected.get("via") else "")
