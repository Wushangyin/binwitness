"""Known vulnerabilities from OSV.dev, severities, fixed versions and CISA KEV flags."""
from __future__ import annotations

import functools
import math
import re
from concurrent.futures import ThreadPoolExecutor

from binwitness.net import Net, NetError
from binwitness.versions import compare

OSV = "https://api.osv.dev/v1"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
OSV_ECOSYSTEM = {"maven": "Maven", "npm": "npm"}


def query(net: Net, packages: list[tuple[str, str, str]], workers: int = 16) -> tuple[dict, list[str]]:
    """(ecosystem, name, version) -> full OSV records.

    Ids come from querybatch (one request per 500 packages); records are fetched by id and cached across
    scans, refetched only when querybatch reports a newer ``modified`` time than the cached copy."""
    wanted: dict[tuple, list[tuple[str, str]]] = {}
    failures = []
    for start in range(0, len(packages), 500):
        chunk = packages[start:start + 500]
        bodies = [{"package": {"name": n, "ecosystem": OSV_ECOSYSTEM[e]}, "version": v} for e, n, v in chunk]
        try:
            results = (net.post_json(f"{OSV}/querybatch", {"queries": bodies}) or {}).get("results", [])
        except NetError as error:
            failures += [f"OSV {n}@{v}: {error}" for _, n, v in chunk]
            continue
        for package, body, result in zip(chunk, bodies, results):
            hits = [(x["id"], x.get("modified", "")) for x in result.get("vulns", [])]
            token = result.get("next_page_token")
            try:
                while token:
                    page = net.post_json(f"{OSV}/query", body | {"page_token": token}) or {}
                    hits += [(x["id"], x.get("modified", "")) for x in page.get("vulns", [])]
                    token = page.get("next_page_token")
            except NetError as error:
                failures.append(f"OSV {package[1]}@{package[2]} (later pages): {error}")
            wanted[package] = hits

    def fetch(hit):
        vuln_id, modified = hit
        url = f"{OSV}/vulns/{vuln_id}"
        record = net.get_json(url, stable=True)
        if record is not None and modified and _instant(record.get("modified", "")) < _instant(modified):
            record = net.get_json(url, stable=True, refresh=True)
        return record

    unique = sorted({hit for hits in wanted.values() for hit in hits})
    records = {}
    with ThreadPoolExecutor(workers) as pool:
        for hit, record in zip(unique, pool.map(_guard(fetch), unique)):
            if isinstance(record, Exception):
                failures.append(f"OSV record {hit[0]}: {record}")
            elif record is not None:
                records[hit[0]] = record
    results = {package: [records[i] for i, _ in hits if i in records and not records[i].get("withdrawn")]
               for package, hits in wanted.items()}
    return results, failures


def query_local(db, packages: list[tuple[str, str, str]]) -> dict:
    """Same answer as :func:`query`, from a local copy of OSV."""
    by_name: dict[tuple[str, str], list[dict]] = {}
    results = {}
    for ecosystem, name, version in packages:
        if (ecosystem, name) not in by_name:
            by_name[(ecosystem, name)] = db.osv_records(ecosystem, name)
        results[(ecosystem, name, version)] = [r for r in by_name[(ecosystem, name)]
                                               if affects(r, ecosystem, name, version)]
    return results


def affects(record: dict, ecosystem: str, name: str, version: str) -> bool:
    """OSV's matching rule (OSV schema, "Evaluation"): an enumerated version, or a version inside one of
    the ``ECOSYSTEM`` / ``SEMVER`` ranges. ``GIT`` ranges name commits, which a binary does not carry."""
    for affected in record.get("affected", []):
        package = affected.get("package") or {}
        if package.get("ecosystem") != OSV_ECOSYSTEM[ecosystem] or package.get("name") != name:
            continue
        if version in affected.get("versions", []):
            return True
        if any(r.get("type") in ("ECOSYSTEM", "SEMVER") and _within(ecosystem, version, r.get("events", []))
               for r in affected.get("ranges", [])):
            return True
    return False


def _within(ecosystem: str, version: str, events: list[dict]) -> bool:
    limits = [e["limit"] for e in events if "limit" in e]
    if limits and not any(x == "*" or compare(ecosystem, version, x) < 0 for x in limits):
        return False

    def order(a: str, b: str) -> int:
        if a == b:
            return 0
        # "0" stands for "before the first version", whatever the ecosystem's version syntax.
        return -1 if a == "0" else 1 if b == "0" else compare(ecosystem, a, b)

    bounds = [(kind, event[kind]) for event in events for kind in ("introduced", "fixed", "last_affected")
              if kind in event]
    inside = False
    for kind, bound in sorted(bounds, key=lambda pair: functools.cmp_to_key(order)(pair[1])):
        if kind == "introduced" and order(version, bound) >= 0:
            inside = True
        elif kind == "fixed" and order(version, bound) >= 0:
            inside = False
        elif kind == "last_affected" and order(version, bound) > 0:
            inside = False
    return inside


def _instant(stamp: str) -> str:
    # querybatch states microseconds, the record itself nanoseconds ("...55.751943Z", "...55.751943207Z"). As
    # text the longer form sorts first, so every cached record looked stale and was fetched again.
    head, _, fraction = stamp.rstrip("Z").partition(".")
    return f"{head}.{fraction[:6]:0<6}"


def kev(net: Net) -> dict[str, str]:
    """CVE -> date added to CISA's Known Exploited Vulnerabilities catalog."""
    data = net.get_json(KEV) or {}
    return {v["cveID"]: v.get("dateAdded", "") for v in data.get("vulnerabilities", [])}


def key_of(record: dict) -> str:
    """One finding per CVE: GHSA and CVE records of the same flaw are aliases of each other."""
    ids = [record["id"], *record.get("aliases", [])]
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else record["id"]


def severity(record: dict) -> tuple[str, str, str | None, float | None]:
    """(label, source, vector, score)."""
    vector = next((s["score"] for s in record.get("severity", []) if s.get("type") == "CVSS_V3"), None)
    score = cvss3_score(vector) if vector else None
    if record["id"].startswith("MAL-"):
        return "CRITICAL", "malicious package", vector, score
    stated = ((record.get("database_specific") or {}).get("severity") or "").upper()
    stated = {"MODERATE": "MEDIUM"}.get(stated, stated)
    if stated in SEVERITIES[:4]:
        return stated, "advisory", vector, score
    if score is not None:
        return rating(score), "CVSS v3 base score", vector, score
    vector4 = next((s["score"] for s in record.get("severity", []) if s.get("type") == "CVSS_V4"), None)
    return "UNKNOWN", "none", vector4, None


def fixed_versions(record: dict, ecosystem: str, name: str) -> list[str]:
    out = []
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") == OSV_ECOSYSTEM[ecosystem] and package.get("name") == name:
            for range_ in affected.get("ranges", []):
                out += [e["fixed"] for e in range_.get("events", []) if "fixed" in e]
    return list(dict.fromkeys(out))


def rating(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string (FIRST specification, section 7.1)."""
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        changed = metrics["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
        impact_base = 1 - math.prod(1 - _WEIGHTS["C"][metrics[m]] for m in ("C", "I", "A"))
        exploitability = (8.22 * _WEIGHTS["AV"][metrics["AV"]] * _WEIGHTS["AC"][metrics["AC"]] * privileges
                          * _WEIGHTS["UI"][metrics["UI"]])
    except KeyError:
        return None
    impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15 if changed else 6.42 * impact_base
    if impact <= 0:
        return 0.0
    total = min(1.08 * (impact + exploitability), 10) if changed else min(impact + exploitability, 10)
    return _roundup(total)


def _roundup(value: float) -> float:
    integer = round(value * 100000)
    return integer / 100000.0 if integer % 10000 == 0 else (math.floor(integer / 10000) + 1) / 10.0


def summary(record: dict) -> str:
    text = record.get("summary") or record.get("details") or ""
    return re.sub(r"\s+", " ", text).strip()[:200]


def _guard(function):
    def run(argument):
        try:
            return function(argument)
        except NetError as error:
            return error
    return run
