"""Result files: native JSON, CycloneDX 1.5 SBOM with vulnerabilities, CSV tables, terminal summary."""
from __future__ import annotations

import csv
import json
import uuid
from pathlib import Path

from binwitness import __version__
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
    for c in result["components"]:
        group, name = c["name"].split(":", 1) if c["ecosystem"] == "maven" else ("", c["name"])
        technique, confidence = _TECHNIQUE[c["confidence"]]
        entry = {"type": "library", "bom-ref": c["purl"], "name": name, "version": c["version"], "purl": c["purl"]}
        if group:
            entry["group"] = group
        if c["scope"] in _SCOPE:
            entry["scope"] = _SCOPE[c["scope"]]
        if len(c["files"]) == 1:
            entry["hashes"] = [{"alg": "SHA-1", "content": c["files"][0]["sha1"]},
                               {"alg": "SHA-256", "content": c["files"][0]["sha256"]}]
        license_ = c.get("license") or {}
        if license_.get("expressions"):
            entry["licenses"] = [{"expression": e} for e in license_["expressions"]][:1]
        elif license_.get("names"):
            entry["licenses"] = [{"license": {"name": n}} for n in license_["names"]]
        entry["evidence"] = {
            "identity": {"field": "purl", "confidence": confidence,
                         "methods": [{"technique": _TECHNIQUE[e["confidence"]][0],
                                      "confidence": _TECHNIQUE[e["confidence"]][1], "value": e["method"]}
                                     for e in c["evidence"]]},
            "occurrences": [{"location": loc} for loc in c["locations"]],
        }
        properties = [{"name": "binwitness:published", "value": f["published"]} for f in c["files"]]
        properties += [{"name": "binwitness:also-published-as", "value": p}
                       for p in dict.fromkeys(p for f in c["files"] for p in f.get("also_published_as", []))]
        properties += [{"name": "binwitness:contained-in", "value": p} for p in c["contained_in"]]
        if properties:
            entry["properties"] = properties
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
                 "affects": [{"ref": ref} for ref in v["affects"]]}
        if v["published"]:
            entry["published"] = v["published"]
        if v["aliases"]:
            entry["references"] = [{"id": a, "source": {"name": "OSV",
                                                         "url": f"https://osv.dev/vulnerability/{a}"}}
                                   for a in v["aliases"]]
        if v["kev_date_added"]:
            entry["properties"] = [{"name": "binwitness:cisa-kev-date-added", "value": v["kev_date_added"]}]
        vulnerabilities.append(entry)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": result["finished"],
                     "tools": {"components": [{"type": "application", "name": "binwitness",
                                               "version": __version__}]}},
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def _counts(component: dict, table: dict) -> list[int]:
    levels = [table[k]["severity"] for k in component["vulnerabilities"]]
    return [levels.count(s) for s in SEVERITIES]


def components_csv(result: dict, path: Path):
    table = result["vulnerabilities"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["ecosystem", "name", "version", "purl", "scope", "confidence", "identified by",
                         "published artifact", "also published as", "contained in", "license family", "licenses",
                         *[s.lower() for s in SEVERITIES], "vulnerabilities", "occurrences", "first location"])
        for c in result["components"]:
            license_ = c.get("license") or {}
            writer.writerow([
                c["ecosystem"], c["name"], c["version"], c["purl"], c["scope"], c["confidence"],
                "; ".join(e["method"] for e in c["evidence"]),
                "; ".join(sorted({f["published"] for f in c["files"]})),
                "; ".join(dict.fromkeys(p for f in c["files"] for p in f.get("also_published_as", []))),
                "; ".join(c["contained_in"]),
                license_.get("family", ""), "; ".join(license_.get("expressions") or license_.get("names") or []),
                *_counts(c, table), " ".join(c["vulnerabilities"]), len(c["locations"]), c["locations"][0]])


def vulnerabilities_csv(result: dict, path: Path):
    with path.open("w", newline="", encoding="utf-8") as handle:
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
    s = result["summary"]
    c, j, v = s["components"], s["jars"], s["vulnerabilities"]
    lines = [
        f"components   {c['total']}  ({', '.join(f'{k} {n}' for k, n in sorted(c['by_ecosystem'].items()))}; "
        f"exact {c['by_confidence'].get('exact', 0)}, content {c['by_confidence'].get('content', 0)}, "
        f"declared {c['by_confidence'].get('declared', 0)})",
        f"jars         {j['distinct_files']} distinct: third-party {j['third_party']}, first-party {j['first_party']}, "
        f"unidentified {j['unidentified']}",
    ]
    if j["differ_from_published"] or j["not_on_central"] or j["repackaged"]:
        lines.append(f"             {j['differ_from_published']} differ from the published artifact, "
                     f"{j['repackaged']} repackaged with unchanged contents"
                     + (f" ({j['copies_of_identified_jars']} by the entries of another jar in the delivery)"
                        if j.get("copies_of_identified_jars") else "")
                     + f", {j['not_on_central']} declare coordinates not found on Maven Central")
    lines.append(f"vulns        {v['total']} distinct: " + ", ".join(
        f"{k.lower()} {n}" for k, n in v["by_severity"].items() if n)
        + (f"; known exploited {v['known_exploited']}" if v["known_exploited"] else "")
        + (f"; MALICIOUS {v['malicious_packages']}" if v["malicious_packages"] else ""))
    lines.append("licenses     " + ", ".join(f"{k} {n}" for k, n in sorted(s["licenses"]["by_family"].items())))
    if result["warnings"]:
        lines.append(f"warnings     {len(result['warnings'])} (see binwitness.json)")
    return "\n".join(lines)
