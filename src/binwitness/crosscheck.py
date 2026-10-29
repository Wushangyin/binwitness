"""Check another scanner's findings against a binwitness result, finding by finding.

Scanners that match advisories to components by product name (CPE) attach an advisory to every module of a
product; registries that record the affected package precisely cannot see advisories nobody attributed to a
package. Disagreements are therefore classified against GitHub's reviewed advisory database, which states
the affected package and version range of each advisory.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from binwitness.net import Net, NetError
from binwitness.versions import in_range

GITHUB = "https://api.github.com"
CLASSES = {
    "confirmed": "GitHub lists this package and version as affected (OSV returned nothing)",
    "bundled-module": "affects a module bundled inside this all-in-one or shaded artifact",
    "version-not-affected": "GitHub lists this package, but this version is outside the affected range",
    "same-project-other-module": "advisory names another module of the same project, not this one",
    "other-package": "advisory names a different package or ecosystem",
    "unattributed": "upstream advisory names no package (GitHub unreviewed); needs manual review",
    "no-github-record": "no GitHub advisory for this CVE",
    "tool-specific-id": "identifier not issued by CVE or GitHub; cannot be checked against public data",
    "lookup-failed": "GitHub lookup failed",
}


def load_other(path: str) -> dict[tuple[str, str, str], set[str]]:
    """(ecosystem, name, version) -> vulnerability ids. CSV columns ``component,version,vulnerability``
    (component as ``group:artifact``, ``npm:name`` or a purl; blank vulnerability = identified, none found),
    or a CycloneDX JSON document with a vulnerabilities section."""
    text = open(path, encoding="utf-8-sig").read()
    found: dict[tuple[str, str, str], set[str]] = {}
    if text.lstrip().startswith("{"):
        document = json.loads(text)
        by_ref = {}
        for component in _flatten(document.get("components", [])):
            key = _from_purl(component.get("purl", ""))
            if key:
                by_ref[component.get("bom-ref", component["purl"])] = key
                found.setdefault(key, set())
        for vulnerability in document.get("vulnerabilities", []):
            for affected in vulnerability.get("affects", []):
                key = by_ref.get(affected.get("ref"))
                if key:
                    found[key] |= _ids(vulnerability["id"])
        return found
    for row in csv.DictReader(io.StringIO(text)):
        row = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
        component = row.get("component") or row.get("purl") or ""
        key = _from_purl(component) if component.startswith("pkg:") else _from_name(component, row.get("version", ""))
        if not key:
            continue
        found.setdefault(key, set())
        if row.get("vulnerability"):
            found[key] |= _ids(row["vulnerability"])
    return found


def _ids(text: str) -> set[str]:
    # Tools often pair a public identifier with their own ("CVE-2023-1|XVE-2023-9", "XVE-9(CVE-2023-1)");
    # the public one is what can be checked. A cell with none is kept whole as a tool-specific id.
    public = {m.upper() for m in re.findall(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b", text, re.I)}
    return public or {text.strip().upper()}


def _flatten(components):
    for component in components:
        yield component
        yield from _flatten(component.get("components", []))


def _from_purl(value: str):
    match = re.match(r"^pkg:(maven|npm)/(.+)@([^?#]+)", value)
    if not match:
        return None
    ecosystem, path, version = match.groups()
    path = urllib.parse.unquote(path)
    name = path.replace("/", ":", 1) if ecosystem == "maven" else path
    return ecosystem, name, urllib.parse.unquote(version)


def _from_name(component: str, version: str):
    if not version:
        return None
    if component.startswith("npm:"):
        return "npm", component[4:], version
    if component.count(":") == 1:
        return "maven", component, version
    return None


def github_token() -> str | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token or not shutil.which("gh"):
        return token
    done = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
    return done.stdout.strip() or None if done.returncode == 0 else None


def advisories(net: Net, cve: str, kind: str, token: str | None) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return net.get_json(f"{GITHUB}/advisories?cve_id={cve}&type={kind}&per_page=100", headers=headers) or []


def classify(net: Net, ecosystem: str, name: str, version: str, vuln_id: str, bundled: list[tuple[str, str]],
             token: str | None, same_file: list[tuple[str, str]] = ()) -> tuple[str, str]:
    """``same_file``: (name, version) the identical file is also published under; an advisory naming one of
    them names this component."""
    if not re.match(r"^(CVE-\d{4}-\d+|GHSA-[\w-]+)$", vuln_id):
        return "tool-specific-id", ""
    try:
        if vuln_id.startswith("GHSA-"):
            records = [r for r in [_ghsa(net, vuln_id, token)] if r]
        else:
            records = advisories(net, vuln_id, "reviewed", token)
        if not records:
            unreviewed = advisories(net, vuln_id, "unreviewed", token) if vuln_id.startswith("CVE-") else []
            return ("unattributed", unreviewed[0]["ghsa_id"]) if unreviewed else ("no-github-record", "")
    except NetError as error:
        return "lookup-failed", str(error)
    named = []
    for record in records:
        for entry in record.get("vulnerabilities") or []:
            package = entry.get("package") or {}
            named.append((package.get("ecosystem", ""), package.get("name", ""),
                          entry.get("vulnerable_version_range") or ""))
    if not named:
        return "unattributed", records[0].get("ghsa_id", "")
    for own_name, own_version in [(name, version), *same_file]:
        mine = [r for e, n, r in named if e == ecosystem and n == own_name]
        if mine:
            if any(in_range(ecosystem, own_version, r) for r in mine):
                return "confirmed", "; ".join(mine)
            return "version-not-affected", "; ".join(mine)
    for module, module_version in bundled:
        ranges = [r for e, n, r in named if e == ecosystem and n == module]
        if any(in_range(ecosystem, module_version, r) for r in ranges):
            return "bundled-module", f"{module} {module_version}"
    detail = ", ".join(sorted({f"{n} ({e})" for e, n, _ in named}))
    if ecosystem == "maven" and any(e == "maven" and n.split(":")[0] == name.split(":")[0] for e, n, _ in named):
        return "same-project-other-module", detail
    if ecosystem == "npm" and name.startswith("@") and any(n.split("/")[0] == name.split("/")[0]
                                                           for e, n, _ in named if e == "npm"):
        return "same-project-other-module", detail
    return "other-package", detail


def _ghsa(net: Net, ghsa: str, token: str | None):
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return net.get_json(f"{GITHUB}/advisories/{ghsa}", headers=headers)


def crosscheck(result: dict, other: dict[tuple[str, str, str], set[str]], net: Net, workers: int = 4) -> dict:
    table = result["vulnerabilities"]
    ours, ids_of = {}, {}
    bundled: dict[str, list[tuple[str, str]]] = {}
    for c in result["components"]:
        key = (c["ecosystem"], c["name"], c["version"])
        ours[key] = set(c["vulnerabilities"])
        ids_of[key] = {alias for k in c["vulnerabilities"] for alias in [k, *table[k]["aliases"]]}
        for parent in c["contained_in"]:
            bundled.setdefault(parent, []).append((c["name"], c["version"]))
    purls = {(c["ecosystem"], c["name"], c["version"]): c["purl"] for c in result["components"]}
    # The other tool may name a file by another coordinate it is published under (a republished groupId).
    same_file = {}
    for c in result["components"]:
        for alias in dict.fromkeys(p for f in c["files"] for p in f.get("also_published_as", [])):
            key = _from_purl(alias)
            if key and key not in ours:
                same_file.setdefault((c["ecosystem"], c["name"], c["version"]), []).append(key)
    named_as = {alias: key for key, aliases in same_file.items() for alias in aliases}
    merged: dict[tuple[str, str, str], set[str]] = {}
    for key, ids in other.items():
        merged.setdefault(named_as.get(key, key), set()).update(ids)
    other = merged
    common = sorted(set(ours) & set(other))
    token = github_token()

    both, only_ours, pending = [], [], []
    for key in common:
        label = f"{key[1]}@{key[2]}"
        theirs = other[key]
        matched = {t for t in theirs if t in ids_of[key]}
        for vuln in sorted(ours[key]):
            aliases = {vuln, *table[vuln]["aliases"]}
            if aliases & theirs:
                both.append({"component": label, "id": vuln, "severity": table[vuln]["severity"]})
            else:
                only_ours.append({"component": label, "id": vuln, "severity": table[vuln]["severity"],
                                  "published": table[vuln]["published"]})
        for vuln in sorted(theirs - matched):
            pending.append((key, vuln, bundled.get(purls[key], [])))

    def run(task):
        (ecosystem, name, version), vuln, inside = task
        return classify(net, ecosystem, name, version, vuln, inside, token,
                        [(n, v) for _, n, v in same_file.get((ecosystem, name, version), [])])

    with ThreadPoolExecutor(workers) as pool:
        verdicts = list(pool.map(run, pending))
    only_theirs = [{"component": f"{key[1]}@{key[2]}", "id": vuln, "class": verdict, "detail": detail}
                   for (key, vuln, _), (verdict, detail) in zip(pending, verdicts)]

    ours_versions = {(e, n) for e, n, _ in ours}
    theirs_only = sorted(set(other) - set(ours))
    return {
        "summary": {
            "components_in_both": len(common),
            "findings_in_both": len(both),
            "only_ours": len(only_ours),
            "only_theirs": len(only_theirs),
            "only_theirs_by_class": dict(Counter(x["class"] for x in only_theirs).most_common()),
            "distinct_ids": {"ours": len({x["id"] for x in both + only_ours}),
                             "theirs": len({v for k in common for v in other[k]}),
                             "only_theirs": len({x["id"] for x in only_theirs})},
            "github_token": bool(token),
        },
        "classes": CLASSES,
        "both": both,
        "only_ours": only_ours,
        "only_theirs": only_theirs,
        "identification": {
            "theirs_other_version": [f"{n}@{v}" for e, n, v in theirs_only if (e, n) in ours_versions],
            "theirs_not_ours": [f"{n}@{v}" for e, n, v in theirs_only if (e, n) not in ours_versions],
            "ours_not_theirs": len(set(ours) - set(other)),
        },
        "data_sources": net.provenance(),
    }
