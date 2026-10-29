"""MCP server: an AI assistant starts scans and reads their results through the Model Context Protocol.

``binwitness mcp`` serves it over stdio. Only :func:`build_server` touches the MCP SDK (the ``mcp`` extra);
the service is plain Python, so the scanner itself never needs the SDK.

Answers are sized for a model's context: lists are paged, file locations are counted rather than listed
unless asked for, and every answer about a result starts with what the result does not cover.
"""
# No ``from __future__ import annotations`` here: the SDK reads the tool signatures in build_server at runtime.
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from binwitness import __version__, upgrades, vulns
from binwitness.crosscheck import CLASSES, crosscheck, load_other
from binwitness.localdb import LocalDb
from binwitness.maven import CENTRAL
from binwitness.net import Net, NetError, default_cache_dir
from binwitness.output import INCOMPLETE, families_of, finding_advice, upgrade_text, worst_findings
from binwitness.vulns import SEVERITIES

# In the order of what leaves the machine: nothing, what the local datasets lack, everything.
LOOKUPS = ("local", "auto", "online")
PAGE = 20
MAX_PAGE = 100
LOCATIONS_SHOWN = 200
DETAILS_SHOWN = 4000
REFERENCES_SHOWN = 20
SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")

STATEMENT = ("Findings are the advisories OSV attributes to the components that were identified, as of the dates "
             "in data_sources. A component without findings has no such advisory as of then, which is not evidence "
             "that it has no flaws. Jars and scripts counted under not_identified are not covered, and first-party "
             "jars are not looked up. There is no reachability analysis: nothing here says whether the application "
             "uses the affected code.")
PLAN_NOTES = {
    "compatibility": "Each target is the nearest published version outside the package's advisories. Whether the "
                     "application builds and works with it is not checked, and there is no reachability analysis.",
    "bom-managed": "A Maven dependency's version is often set by a BOM or parent POM (a framework's dependency "
                   "management): change it there, or override it in dependencyManagement, rather than in the module "
                   "that uses it.",
    "family": "A release family is the artifacts of one group at one version (spring-core, spring-web and "
              "spring-beans 5.3.4): they are released together, so the plan gives them one step and one target that "
              "every member is published at, weighed by the advisories of all of them. per_member keeps what each "
              "artifact would need alone.",
    "transitive-npm": "An npm package may be a dependency of a dependency: upgrade the package that requires it, "
                      "or pin it with overrides (npm) or resolutions (yarn).",
}
SENDS_SCAN = ("Network use follows the lookup level: local sends nothing; auto asks public services only what the "
              "local datasets (binwitness db sync) lack; online asks them everything. What is sent: SHA-1 hashes of "
              "jars and SHA-256 hashes of JavaScript files that may be copied libraries (deps.dev, Maven Central, "
              "jsDelivr), component "
              "coordinates and versions (OSV, Maven Central, npm registry, license sources), and with class_search "
              "one class name per jar nothing else identified. File contents are never sent.")


class Refused(Exception):
    """A request the server does not carry out; the message says why and what to do instead."""


def default_results_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
    else:
        base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "binwitness" / "scans"


@dataclass
class Config:
    lookup: str = "auto"  # the most a tool call may use; a call can ask for less
    roots: tuple = ()
    results: Path = field(default_factory=default_results_dir)
    allow_class_search: bool = False
    cache_dir: Path | None = None
    db_dir: Path | None = None
    maven_mirror: str | None = None
    maven_repos: tuple = ()
    workers: int = 16
    max_age: float = 12.0


@dataclass
class _Job:
    directory: Path
    process: subprocess.Popen
    started: float


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _page(items: list, offset: int, limit: int) -> tuple[list, dict]:
    if offset < 0 or limit < 1:
        raise Refused("offset must be 0 or more and limit 1 or more")
    limit = min(limit, MAX_PAGE)
    shown = items[offset:offset + limit]
    return shown, {"total": len(items), "offset": offset, "returned": len(shown),
                   "remaining": max(0, len(items) - offset - len(shown))}


def _rank(severity: str | None) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _threshold(min_severity: str | None) -> int:
    if min_severity is None:
        return len(SEVERITIES)
    if min_severity.upper() not in SEVERITIES:
        raise Refused(f"min_severity is one of {', '.join(s.lower() for s in SEVERITIES)}")
    return SEVERITIES.index(min_severity.upper())


class Service:
    """What the MCP tools do, without the protocol. Each public method answers one tool call."""

    def __init__(self, config: Config, net: Net | None = None, db: LocalDb | None = None,
                 launch=subprocess.Popen):
        if config.lookup not in LOOKUPS:
            raise ValueError(f"lookup is one of {', '.join(LOOKUPS)}")
        self.config = config
        self.roots = tuple(Path(root).resolve() for root in config.roots)
        self.results = Path(config.results)
        mirrors = {CENTRAL: config.maven_mirror.rstrip("/")} if config.maven_mirror else {}
        self.net = net or Net(cache_dir=config.cache_dir or default_cache_dir(), offline=config.lookup == "local",
                              max_age_hours=config.max_age, mirrors=mirrors)
        self._db = db
        self._launch = launch
        self._jobs: dict[str, _Job] = {}
        self._opened: dict[str, Path] = {}
        self._loaded: dict[Path, tuple[tuple, dict]] = {}
        self._lock = threading.Lock()

    # ---- scans --------------------------------------------------------------------------------------

    def start_scan(self, paths: list[str], lookup: str | None = None, vulnerabilities: bool = True,
                   licenses: bool = True, upgrade_advice: bool = True, javascript: bool = True,
                   class_search: bool = False, first_party_groups: list[str] | None = None,
                   first_party_jars: list[str] | None = None, first_party_npm: list[str] | None = None,
                   exclude: list[str] | None = None) -> dict:
        lookup = self._lookup(lookup)
        if class_search and not self.config.allow_class_search:
            raise Refused("class search sends class names to Maven Central and is off on this server; it is "
                          "turned on by starting the server with --allow-class-search")
        if not paths:
            raise Refused("give at least one file or directory to scan")
        inputs = [str(self._under_root(p, "scan")) for p in paths]
        with self._lock:
            running = [i for i, job in self._jobs.items() if job.process.poll() is None]
            if running:
                raise Refused(f"scan {running[0]} is still running and this server runs one at a time; "
                              f"scan_status tells when it is done")
            scan_id = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
            directory = self.results / scan_id
            directory.mkdir(parents=True)
            command = [sys.executable, "-m", "binwitness", "scan", *inputs, "-o", str(directory),
                       "--lookup", lookup, "--workers", str(self.config.workers),
                       "--max-age", str(self.config.max_age)]
            for flag, value in (("--cache-dir", self.config.cache_dir), ("--db-dir", self.config.db_dir),
                                ("--maven-mirror", self.config.maven_mirror)):
                if value:
                    command += [flag, str(value)]
            for flag, values in (("--maven-repo", self.config.maven_repos),
                                 ("--first-party-group", first_party_groups), ("--first-party-jar", first_party_jars),
                                 ("--first-party-npm", first_party_npm), ("--exclude", exclude)):
                for value in values or ():
                    command += [flag, value]
            command += [flag for flag, off in (("--no-vulns", not vulnerabilities), ("--no-licenses", not licenses),
                                                ("--no-upgrades", not upgrade_advice), ("--no-js", not javascript),
                                                ("--class-search", class_search)) if off]
            job = {"id": scan_id, "inputs": inputs, "lookup": lookup, "class_search": class_search,
                   "started": _now(), "served_by": __version__}
            (directory / "job.json").write_text(json.dumps(job, indent=1), "utf-8")
            # The protocol runs over this server's stdin and stdout, so the scan must not touch either.
            with open(directory / "summary.txt", "wb") as out, open(directory / "scan.log", "wb") as err:
                process = self._launch(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self._jobs[scan_id] = _Job(directory, process, time.monotonic())
        return {"scan_id": scan_id, "state": "running", "lookup": lookup, "inputs": inputs,
                "result_dir": str(directory),
                "next": "call scan_status with this scan_id until the state is finished, then overview"}

    def scan_status(self, scan_id: str) -> dict:
        directory = self._directory(scan_id)
        state, detail = self._state(scan_id, directory)
        answer = {"scan_id": scan_id, "state": state, **detail}
        if state == "failed":
            answer["log_tail"] = self._tail(directory / "scan.log", 20)
        elif state == "finished":
            answer["next"] = "overview gives the counts and the worst findings"
        return answer

    def open_result(self, path: str) -> dict:
        target = Path(path).expanduser()
        if target.is_dir():
            target = target / "binwitness.json"
        try:
            target = target.resolve(strict=True)
        except OSError:
            raise Refused(f"no binwitness.json at {path}") from None
        self._load(target)
        scan_id = f"opened-{secrets.token_hex(4)}"
        with self._lock:
            known = next((i for i, p in self._opened.items() if p == target), None)
            scan_id = known or scan_id
            self._opened[scan_id] = target
        return self.overview(scan_id)

    def list_scans(self) -> dict:
        scans = []
        if self.results.is_dir():
            for directory in sorted(self.results.iterdir(), reverse=True):
                if directory.is_dir() and (directory / "job.json").exists():
                    scans.append(self._listing(directory.name, directory))
        scans += [self._listing(scan_id, path.parent, path) for scan_id, path in self._opened.items()]
        return {"results_dir": str(self.results), "scans": scans,
                "scanning": "on, under " + ", ".join(map(str, self.roots)) if self.roots else
                            "off: the server was started without --root, so only open_result works"}

    # ---- reading a result ---------------------------------------------------------------------------

    def overview(self, scan_id: str) -> dict:
        path, result = self._result(scan_id)
        s = result["summary"]
        named = {c["purl"]: c for c in result["components"]}
        families = families_of(result)
        worst = []
        for entry in worst_findings(result)[:10]:
            ref, affected = next(iter(entry["affects"].items()))
            component = named.get(ref)
            worst.append({"id": entry["id"], "severity": entry["severity"], "summary": entry["summary"],
                          "known_exploited_since": entry["kev_date_added"], "malicious": entry["malicious"],
                          "component": ref, "other_components": len(entry["affects"]) - 1,
                          "advice": finding_advice(component, entry["id"], affected,
                                                   families.get(component.get("upgrade_family"))).removeprefix(", ")
                          if component else ""})
        options = result["options"]
        upgrades_block = dict(s.get("upgrades") or {})
        if upgrades_block.get("by_verdict"):
            upgrades_block["meaning"] = {k: upgrades.VERDICT_TEXT[k] for k in upgrades_block["by_verdict"]}
        return {
            "coverage": self._coverage(result, path),
            "scan_id": scan_id,
            "inputs": result["inputs"],
            "components": s["components"],
            "jars": s["jars"],
            "vulnerabilities": s["vulnerabilities"] if options.get("vulnerabilities", True) else "not looked up",
            "worst_findings": worst,
            "worst_findings_total": len(worst_findings(result)),
            "upgrades": upgrades_block if options.get("upgrades") else self._no_upgrades(result),
            "licenses": s["licenses"] if options.get("licenses", True) else "not looked up",
            "warnings": {"total": len(result["warnings"]), "first": result["warnings"][:10]},
            "next": "list_components (min_severity, text), get_component, get_vulnerability, upgrade_plan",
        }

    def list_components(self, scan_id: str, text: str | None = None, min_severity: str | None = None,
                        ecosystem: str | None = None, license_family: str | None = None,
                        verdict: str | None = None, offset: int = 0, limit: int = PAGE) -> dict:
        path, result = self._result(scan_id)
        table, threshold = result["vulnerabilities"], _threshold(min_severity)
        if verdict is not None and verdict not in upgrades.VERDICTS:
            raise Refused(f"verdict is one of {', '.join(upgrades.VERDICTS)}")
        chosen = []
        for c in sorted(result["components"], key=lambda c: c["purl"]):
            if text and text.lower() not in c["purl"].lower():
                continue
            if ecosystem and c["ecosystem"] != ecosystem.lower():
                continue
            if license_family and (c.get("license") or {}).get("family", "unknown") != license_family:
                continue
            if verdict and (c.get("upgrade") or {}).get("verdict") != verdict:
                continue
            severities = [table[k]["severity"] for k in c["vulnerabilities"]]
            if min_severity and not any(_rank(x) <= threshold for x in severities):
                continue
            chosen.append(c)
        shown, paging = _page(chosen, offset, limit)
        return {"coverage": self._coverage(result, path), **paging,
                "components": [self._brief(c, table) for c in shown]}

    def list_unidentified(self, scan_id: str, offset: int = 0, limit: int = PAGE) -> dict:
        path, result = self._result(scan_id)
        shown, paging = _page(result["unidentified"], offset, limit)
        return {"coverage": self._coverage(result, path), **paging,
                "jars": [{"filename": u["filename"], "sha1": u.get("sha1"), "reason": u["reason"],
                          "declared": u.get("declared"), "locations": len(u.get("locations") or [])}
                         for u in shown],
                "unmatched_scripts": len(result["unmatched_scripts"]),
                "note": "these are not covered by the findings; an unidentified jar may be first-party code, a "
                        "rebuilt library or a vendor's own release"}

    def get_component(self, scan_id: str, purl: str, include_locations: bool = False) -> dict:
        path, result = self._result(scan_id)
        table = result["vulnerabilities"]
        component = self._find(result, purl)
        family = families_of(result).get(component.get("upgrade_family"))
        out = {k: v for k, v in component.items()
               if k not in ("locations", "files", "vulnerabilities", "upgrade", "upgrade_family")}
        locations = component.get("locations") or []
        out["location_count"] = len(locations)
        if include_locations:
            out["locations"] = locations[:LOCATIONS_SHOWN]
            out["locations_not_shown"] = max(0, len(locations) - LOCATIONS_SHOWN)
        out["files"] = [{k: (v if k != "locations" or include_locations else len(v)) for k, v in f.items()}
                        for f in component["files"]]
        findings = []
        for key in sorted(component["vulnerabilities"], key=lambda k: (_rank(table[k]["severity"]), k)):
            entry, affected = table[key], table[key]["affects"].get(component["purl"], {"fixed": []})
            findings.append({"id": key, "aliases": entry["aliases"], "severity": entry["severity"],
                             "summary": entry["summary"], "known_exploited_since": entry["kev_date_added"],
                             "malicious": entry["malicious"], "fixed": affected["fixed"],
                             "via": affected.get("via"),
                             "advice": finding_advice(component, key, affected, family).removeprefix(", ")})
        out["findings"] = findings
        if not findings:
            out["findings_note"] = (
                "not looked up in this scan" if not result["options"].get("vulnerabilities", True) else
                "not checked: the lookup failed or was not in the offline cache"
                if component.get("vulnerabilities_checked") is False else
                "OSV has no advisory for this version as of the dates in data_sources")
        if component.get("upgrade"):
            out["upgrade"] = {**component["upgrade"],
                              "meaning": upgrades.VERDICT_TEXT[component["upgrade"]["verdict"]]}
        if family:
            out["upgrade_family"] = {**family, "meaning": PLAN_NOTES["family"]}
        return {"coverage": self._coverage(result, path), "component": out}

    def get_vulnerability(self, scan_id: str, vuln_id: str) -> dict:
        path, result = self._result(scan_id)
        table = result["vulnerabilities"]
        wanted = vuln_id.strip().upper()
        key = next((k for k, v in table.items() if wanted in {k.upper(), *map(str.upper, v["aliases"]),
                                                              *map(str.upper, v.get("osv_ids", []))}), None)
        if key is None:
            raise Refused(f"{vuln_id} is not among this scan's findings; list_components or get_component shows "
                          f"the ids found")
        entry = table[key]
        named = {c["purl"]: c for c in result["components"]}
        families = families_of(result)
        affects = [{"component": ref, "fixed": x["fixed"], "via": x.get("via"),
                    "advice": finding_advice(named[ref], key, x, families.get(named[ref].get("upgrade_family")))
                    .removeprefix(", ") if ref in named else ""}
                   for ref, x in entry["affects"].items()]
        packages = {(named[ref]["ecosystem"], named[ref]["name"]) for ref in entry["affects"] if ref in named}
        return {"coverage": self._coverage(result, path),
                "vulnerability": {k: v for k, v in entry.items() if k != "affects"}, "affects": affects,
                "advisories": [self._advisory(osv_id, packages) for osv_id in entry.get("osv_ids") or [key]]}

    def upgrade_plan(self, scan_id: str, min_severity: str | None = None, offset: int = 0,
                     limit: int = PAGE) -> dict:
        path, result = self._result(scan_id)
        if not result["options"].get("upgrades"):
            return {"coverage": self._coverage(result, path), "plan": [], "note": self._no_upgrades(result)}
        table, threshold = result["vulnerabilities"], _threshold(min_severity)
        steps, hosts, not_checked = [], {}, []
        families = families_of(result)
        for family in families.values():
            ids = [*family["clears"], *family["remaining"]]
            worst = min((table[k]["severity"] for k in ids if k in table), key=_rank, default=None)
            if min_severity and _rank(worst) > threshold:
                continue
            if family["verdict"] == "unverified":
                not_checked.append({"family": family["family"], "reason": family.get("reason")})
                continue
            step = {"action": self._action(family["verdict"]), "family": family["family"],
                    "members": family["members"], "verdict": family["verdict"],
                    "meaning": upgrades.VERDICT_TEXT[family["verdict"]], "target": family["target"],
                    "clears": family["clears"], "remaining": family["remaining"],
                    "introduced": family["introduced"], "worst_severity": worst,
                    "known_exploited": any(table[k]["kev_date_added"] for k in ids if k in table),
                    "caveats": [x["text"] for x in family["caveats"]],
                    # A member with no target of its own and nothing left at the family's target adds only bulk.
                    "per_member": [m for m in family["per_member"]
                                   if m["own_target"] or m["remaining"] or m["introduced"]]}
            if family.get("same_line"):
                step["same_line"] = family["same_line"]
            steps.append(step)
        for c in sorted(result["components"], key=lambda c: c["purl"]):
            block = c.get("upgrade")
            if not block or c.get("upgrade_family") in families:
                continue
            ids = [*block["clears"], *block["remaining"]]
            worst = min((table[k]["severity"] for k in ids if k in table), key=_rank, default=None)
            if min_severity and _rank(worst) > threshold:
                continue
            if block["verdict"] == "unverified":
                not_checked.append({"component": c["purl"], "reason": block.get("reason"),
                                    "osv_fixed": block.get("osv_fixed")})
                continue
            step = {"component": c["purl"], "ecosystem": c["ecosystem"], "version": c["version"],
                    "verdict": block["verdict"], "meaning": upgrades.VERDICT_TEXT[block["verdict"]],
                    "target": block["target"], "clears": block["clears"], "remaining": block["remaining"],
                    "introduced": block["introduced"], "worst_severity": worst,
                    "known_exploited": any(table[k]["kev_date_added"] for k in ids if k in table),
                    "caveats": [x["text"] for x in block["caveats"]]}
            for extra in ("same_line", "alternatives", "target_package", "same_coordinates", "osv_fixed",
                          "fix_versions_not_published"):
                if block.get(extra):
                    step[extra] = block[extra]
            if c["contained_in"] and not c["files"]:
                for host in c["contained_in"]:
                    hosts.setdefault(host, []).append(step)
            else:
                steps.append({"action": self._action(block["verdict"]), **step})
        named = {c["purl"]: c for c in result["components"]}
        for host, bundled in hosts.items():
            own = (named.get(host) or {}).get("upgrade")
            steps.append({"action": "change the host", "host": host, "bundled": bundled,
                          "host_upgrade": upgrade_text(own) if own else None,
                          "worst_severity": min((b["worst_severity"] for b in bundled), key=_rank),
                          "known_exploited": any(b["known_exploited"] for b in bundled),
                          "meaning": upgrades.CAVEATS["embedded-in-host"].format(hosts=host)})
        order = {"remove": 0}
        steps.sort(key=lambda x: (order.get(x["action"], 1), not x["known_exploited"], _rank(x["worst_severity"]),
                                  x.get("component") or x.get("family") or x.get("host")))
        shown, paging = _page(steps, offset, limit)
        ecosystems = {c["ecosystem"] for c in result["components"] if c.get("upgrade")}
        notes = [PLAN_NOTES["compatibility"]] + [PLAN_NOTES[k] for k, e in (("bom-managed", "maven"),
                                                                             ("transitive-npm", "npm"))
                                                 if e in ecosystems] + ([PLAN_NOTES["family"]] if families else [])
        return {"coverage": self._coverage(result, path), **paging, "plan": shown, "notes": notes,
                "not_checked": {"total": len(not_checked), "first": not_checked[:PAGE]},
                "by_verdict": result["summary"].get("upgrades", {}).get("by_verdict", {})}

    def crosscheck(self, scan_id: str, other_path: str, limit: int = PAGE) -> dict:
        if self.config.lookup == "local":
            raise Refused("crosscheck asks GitHub's advisory database and OSV about each finding the two tools "
                          "disagree on; this server runs with --lookup local, so it sends nothing")
        path, result = self._result(scan_id)
        other = self._under_root(other_path, "read")
        try:
            findings = load_other(str(other))
        except (ValueError, KeyError, UnicodeDecodeError) as error:
            raise Refused(f"cannot read {other_path} as CycloneDX JSON or a component,version,vulnerability CSV: "
                          f"{error}") from None
        report = crosscheck(result, findings, self.net, workers=min(self.config.workers, 4))
        directory = self.results / scan_id
        directory.mkdir(parents=True, exist_ok=True)
        saved = directory / f"crosscheck-{other.stem}.json"
        saved.write_text(json.dumps(report, ensure_ascii=False, indent=1), "utf-8")
        s = report["summary"]
        failed = s["only_theirs_by_class"].get("lookup-failed", 0)
        examples = {}
        for finding in report["only_theirs"]:
            examples.setdefault(finding["class"], [])
            if len(examples[finding["class"]]) < limit:
                examples[finding["class"]].append(finding)
        return {"coverage": self._coverage(result, path), "summary": s,
                "classes": {k: CLASSES[k] for k in s["only_theirs_by_class"]},
                "only_theirs": examples, "identification": report["identification"],
                "incomplete": {"lookup_failed": failed, "note": (
                    f"{failed} findings could not be classified (GitHub lookups failed"
                    + ("; without a token GitHub allows 60 lookups an hour: set GITHUB_TOKEN or run gh auth login"
                       if not s["github_token"] else "") + ")") if failed else None},
                "report": str(saved)}

    # ---- internals ----------------------------------------------------------------------------------

    def _lookup(self, lookup: str | None) -> str:
        ceiling = self.config.lookup
        if lookup is None:
            return ceiling
        if lookup not in LOOKUPS:
            raise Refused(f"lookup is one of {', '.join(LOOKUPS)}")
        if LOOKUPS.index(lookup) > LOOKUPS.index(ceiling):
            raise Refused(f"this server allows lookups up to {ceiling!r}; {lookup!r} would send more than that")
        return lookup

    def _under_root(self, path: str, purpose: str) -> Path:
        if not self.roots:
            raise Refused(f"the server was started without --root, so it does not {purpose} files; start it with "
                          f"--root DIR to allow files under DIR")
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except OSError:
            raise Refused(f"not found: {path}") from None
        if not any(resolved == root or resolved.is_relative_to(root) for root in self.roots):
            raise Refused(f"{path} is outside the directories this server may {purpose} "
                          f"({', '.join(map(str, self.roots))})")
        return resolved

    def _directory(self, scan_id: str) -> Path:
        if scan_id in self._opened:
            return self._opened[scan_id].parent
        if not SCAN_ID.match(scan_id or "") or not (self.results / scan_id / "job.json").exists():
            raise Refused(f"no scan {scan_id!r}; list_scans shows the known ones")
        return self.results / scan_id

    def _state(self, scan_id: str, directory: Path) -> tuple[str, dict]:
        job = self._jobs.get(scan_id)
        record_path = directory / "job.json"
        record = json.loads(record_path.read_text("utf-8")) if record_path.exists() else {}
        if job is not None:
            code = job.process.poll()
            elapsed = round(time.monotonic() - job.started)
            if code is None:
                return "running", {"elapsed_seconds": elapsed, "progress": self._tail(directory / "scan.log", 1)}
            if "exit_code" not in record:
                record.update(exit_code=code, finished=_now(), elapsed_seconds=elapsed)
                record_path.write_text(json.dumps(record, indent=1), "utf-8")
        if (directory / "binwitness.json").exists():
            return "finished", {"elapsed_seconds": record.get("elapsed_seconds"), "finished": record.get("finished")}
        if "exit_code" in record:
            return "failed", {"exit_code": record["exit_code"]}
        return "unknown", {"note": "started by an earlier server process that has since stopped; no result yet"}

    def _listing(self, scan_id: str, directory: Path, path: Path | None = None) -> dict:
        record = {}
        if (directory / "job.json").exists() and path is None:
            record = json.loads((directory / "job.json").read_text("utf-8"))
        state = self._state(scan_id, directory)[0] if path is None else "opened"
        entry = {"scan_id": scan_id, "state": state, "inputs": record.get("inputs"),
                 "started": record.get("started")}
        result_path = path or directory / "binwitness.json"
        if result_path.exists():
            try:
                result = self._load(result_path)
            except Refused as error:
                entry["error"] = str(error)
            else:
                s = result["summary"]
                entry.update(inputs=entry["inputs"] or [i["name"] for i in result["inputs"]],
                             finished=result.get("finished"), components=s["components"]["total"],
                             vulnerabilities=s["vulnerabilities"]["total"],
                             lookups_complete=not s.get("incomplete"), result=str(result_path))
        return entry

    def _result(self, scan_id: str) -> tuple[Path, dict]:
        directory = self._directory(scan_id)
        path = self._opened.get(scan_id) or directory / "binwitness.json"
        if not path.exists():
            state = self._state(scan_id, directory)[0]
            raise Refused(f"scan {scan_id} is {state} and has no result yet; scan_status tells more")
        return path, self._load(path)

    def _load(self, path: Path) -> dict:
        stat = path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
        with self._lock:
            held = self._loaded.get(path)
            if held and held[0] == stamp:
                return held[1]
        try:
            result = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError) as error:
            raise Refused(f"cannot read {path} as JSON: {error}") from None
        if not (isinstance(result, dict) and (result.get("tool") or {}).get("name") == "binwitness"
                and "components" in result):
            raise Refused(f"{path} is not a binwitness result")
        with self._lock:
            self._loaded[path] = (stamp, result)
        return result

    def _coverage(self, result: dict, path: Path) -> dict:
        s, options = result["summary"], result["options"]
        incomplete = s.get("incomplete") or {}
        off = [label for label, on in (("vulnerability lookup", options.get("vulnerabilities", True)),
                                       ("license lookup", options.get("licenses", True)),
                                       ("vendored JavaScript lookup", options.get("scan_js", True)),
                                       ("upgrade advice", options.get("upgrades", False)))
               if not on]
        return {
            "lookups_complete": not incomplete,
            "not_checked": {k: {"count": n, "meaning": INCOMPLETE.get(k, k).format(n=n)}
                            for k, n in incomplete.items()},
            "not_identified": {"unidentified_jars": len(result["unidentified"]),
                               "unmatched_scripts": len(result["unmatched_scripts"]),
                               "bundled_scripts": len(result.get("bundled_scripts") or []),
                               "scripts_without_version": len(result.get("scripts_without_version") or []),
                               "first_party_jars": len(result["first_party"])},
            # Ecosystems binwitness does not read, by the dependency files found: their dependencies are absent.
            "not_covered": {k: len(v) for k, v in (result.get("not_covered") or {}).items()},
            "turned_off": off,
            "statement": STATEMENT,
            "lookup": options.get("lookup"),
            "data_sources": result.get("data_sources"),
            "scanned_by": f"binwitness {result['tool']['version']}",
            "served_by": f"binwitness {__version__}",
            "scan_finished": result.get("finished"),
            "result": str(path),
        }

    @staticmethod
    def _no_upgrades(result: dict) -> str:
        if "upgrades" not in result["options"]:
            return (f"this result was made by binwitness {result['tool']['version']}, before upgrade advice "
                    f"existed; scan again for it")
        return "upgrade advice was not computed (no vulnerability lookup, or turned off)"

    @staticmethod
    def _action(verdict: str) -> str:
        return {"remove-malicious": "remove", "no-published-fix": "replace or remove"}.get(verdict, "upgrade")

    @staticmethod
    def _brief(c: dict, table: dict) -> dict:
        counts: dict[str, int] = {}
        for key in c["vulnerabilities"]:
            counts[table[key]["severity"]] = counts.get(table[key]["severity"], 0) + 1
        return {"purl": c["purl"], "scope": c["scope"], "confidence": c["confidence"],
                "license": (c.get("license") or {}).get("family", "unknown"),
                "findings": {k: counts[k] for k in SEVERITIES if k in counts},
                "known_exploited": any(table[k]["kev_date_added"] for k in c["vulnerabilities"]),
                "vulnerabilities_checked": c.get("vulnerabilities_checked"),
                "upgrade": upgrade_text(c["upgrade"]) if c.get("upgrade") else None,
                "upgrade_family": c.get("upgrade_family"),
                "published": sorted({f["published"] for f in c["files"]}),
                "contained_in": len(c["contained_in"]),
                "locations": len(c.get("locations") or [])}

    @staticmethod
    def _find(result: dict, wanted: str) -> dict:
        """A purl, or a name with or without its version: group:artifact, the artifactId alone, an npm name
        (@scope/name too). Several exact matches are refused by name. A part of a name is never taken as the
        component: "log4j:log4j" is inside "org.apache.logging.log4j:log4j-api", and answering with that would
        hand over another library's findings, so the names containing it are offered instead."""
        components = result["components"]
        exact = [c for c in components if c["purl"] == wanted]
        if exact:
            return exact[0]
        bare = wanted.removeprefix("pkg:")
        at = bare.rfind("@")
        name, version = (bare[:at], bare[at + 1:]) if at > 0 else (bare, "")

        def of_version(found):
            return [c for c in found if not version or c["version"] == version]

        stages = (of_version([c for c in components if c["name"] == name]),
                  of_version([c for c in components if c["ecosystem"] == "maven" and c["name"].split(":", 1)[1] == name]))
        for found in stages:
            if len(found) == 1:
                return found[0]
            if found:
                raise Refused(f"{wanted} matches {len(found)} components: "
                              + ", ".join(c["purl"] for c in found[:10]) + "; give the version or the full purl")
        part = name.lower()
        containing = [c["purl"] for c in components if part in c["name"].lower()]
        if containing:
            raise Refused(f"no component {wanted} in this scan; {len(containing)} name{'s' if len(containing) > 1 else ''} "
                          f"contain{'' if len(containing) > 1 else 's'} it, which may be other libraries: "
                          + ", ".join(containing[:10]) + ("" if len(containing) <= 10 else ", ...")
                          + "; ask for one of them by its full name")
        raise Refused(f"no component {wanted} in this scan; list_components finds it by part of its name")

    def _local_db(self) -> LocalDb | None:
        if self._db is None and self.config.lookup != "online":
            self._db = LocalDb.open(self.config.db_dir)
        return self._db

    def _advisory(self, osv_id: str, packages: set) -> dict:
        record, source = None, None
        db = self._local_db()
        if db is not None:
            for ecosystem, name in sorted(packages):
                if db.has(upgrades.OSV_DATASET[ecosystem]):
                    record = next((r for r in db.osv_records(ecosystem, name) if r.get("id") == osv_id), None)
                    if record:
                        dataset = upgrades.OSV_DATASET[ecosystem]
                        source = f"local {dataset} copy, data as of {db.data_as_of(dataset)}"
                        break
        if record is None and self.config.lookup != "local":
            try:
                record = self.net.get_json(f"{vulns.OSV}/vulns/{osv_id}")
                source = "api.osv.dev"
            except NetError as error:
                return {"id": osv_id, "note": f"the OSV record could not be fetched: {error}"}
        if record is None:
            return {"id": osv_id, "note": "the OSV record is not in the local datasets, and this server runs with "
                                          "--lookup local" if self.config.lookup == "local" else "OSV has no such record"}
        details = record.get("details") or ""
        return {"id": osv_id, "source": source, "summary": record.get("summary"),
                "details": details[:DETAILS_SHOWN], "details_truncated": len(details) > DETAILS_SHOWN,
                "aliases": record.get("aliases", []), "published": record.get("published"),
                "modified": record.get("modified"),
                "cwe_ids": (record.get("database_specific") or {}).get("cwe_ids", []),
                "references": [r.get("url") for r in record.get("references", [])[:REFERENCES_SHOWN]],
                "affected": [{"package": a.get("package"), "ranges": a.get("ranges"),
                              "versions_listed": len(a.get("versions") or [])}
                             for a in record.get("affected", [])
                             if (a.get("package") or {}).get("name") in {n for _, n in packages}]}

    @staticmethod
    def _tail(path: Path, lines: int) -> list[str] | str:
        try:
            with path.open("rb") as handle:
                handle.seek(max(0, path.stat().st_size - 16384))
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            return [] if lines > 1 else ""
        kept = [line for line in text.splitlines() if line.strip()][-lines:]
        return kept if lines > 1 else (kept[-1] if kept else "")


INSTRUCTIONS = """\
binwitness identifies the third-party components inside delivered binaries (jars, wars, container images, \
front-end builds) with the evidence for each, and reports the advisories OSV records for them.

Typical use: start_scan, then scan_status until finished, then overview; drill down with list_components, \
get_component and get_vulnerability; upgrade_plan says which published version leaves each finding behind. \
open_result reads a binwitness.json made earlier on the command line.

When reporting to the user:
- Lead with coverage: name what was not identified or not checked. A component without findings has no \
advisory in the data used, as of its date; do not present that as proof of absence.
- There is no reachability analysis: a finding means the version is affected, not that the application \
uses the affected code.
- An upgrade target's compatibility with the application is not checked; say so when recommending it.
"""


def build_server(service: Service):
    """The MCP server around a service. Raises ImportError when the ``mcp`` extra is not installed."""
    from typing import Annotated, Any, Literal

    from mcp.server import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.types import ToolAnnotations
    from pydantic import Field

    server = MCPServer("binwitness", title="binwitness", version=__version__, instructions=INSTRUCTIONS)
    reading = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    ScanId = Annotated[str, Field(description="scan id from start_scan, open_result or list_scans")]
    Offset = Annotated[int, Field(description="skip this many entries", ge=0)]
    Limit = Annotated[int, Field(description=f"entries to return (at most {MAX_PAGE})", ge=1)]
    Severity = Annotated[Literal["critical", "high", "medium", "low"] | None,
                         Field(description="only entries with a finding at or above this severity")]
    lookup_note = {"local": "this server sends nothing", "auto": "local, or auto (the default)",
                   "online": "local, auto or online (the default)"}[service.config.lookup]

    async def call(method, *args, **kwargs) -> dict[str, Any]:
        import anyio
        try:
            return await anyio.to_thread.run_sync(lambda: method(*args, **kwargs))
        except Refused as refusal:
            raise ToolError(str(refusal)) from None
        except Exception as error:  # the model needs the reason to recover; a bare "error executing" gives none
            raise ToolError(f"{type(error).__name__}: {error}") from None

    @server.tool(title="Start a scan", structured_output=True,
                 annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False,
                                             openWorldHint=service.config.lookup != "local"),
                 description="Scan files or directories (archives, images, builds) in the background and return a "
                             "scan id at once; the result is written to the server's results directory, the inputs "
                             f"are only read. {SENDS_SCAN} Allowed lookup levels: {lookup_note}.")
    async def start_scan(
            paths: Annotated[list[str], Field(description="files or directories under the server's --root "
                                                          "directories")],
            lookup: Annotated[Literal["local", "auto", "online"] | None,
                              Field(description="how much may be asked of online services; default: the server's "
                                                "setting")] = None,
            vulnerabilities: Annotated[bool, Field(description="look up advisories")] = True,
            licenses: Annotated[bool, Field(description="resolve licenses")] = True,
            upgrade_advice: Annotated[bool, Field(description="find the published version that leaves each "
                                                              "finding behind")] = True,
            javascript: Annotated[bool, Field(description="look up vendored JavaScript files")] = True,
            class_search: Annotated[bool, Field(description="identify rebuilt jars by one class name each; sends "
                                                            "those class names to Maven Central; only when the "
                                                            "server allows it")] = False,
            first_party_groups: Annotated[list[str] | None, Field(description="Maven groupId prefixes of the "
                                                                              "user's own code")] = None,
            first_party_jars: Annotated[list[str] | None, Field(description="jar file name prefixes of the "
                                                                            "user's own code")] = None,
            first_party_npm: Annotated[list[str] | None, Field(description="npm name prefixes of the user's own "
                                                                           "code, e.g. @acme/")] = None,
            exclude: Annotated[list[str] | None, Field(description="glob patterns of locations to skip")] = None,
    ) -> dict[str, Any]:
        return await call(service.start_scan, paths, lookup, vulnerabilities, licenses, upgrade_advice, javascript,
                          class_search, first_party_groups, first_party_jars, first_party_npm, exclude)

    @server.tool(title="Scan status", structured_output=True, annotations=reading,
                 description="State of a scan started with start_scan: running (with elapsed time and the last "
                             "progress line), finished, or failed (with the end of its log). Sends nothing.")
    async def scan_status(scan_id: ScanId) -> dict[str, Any]:
        return await call(service.scan_status, scan_id)

    @server.tool(title="Open a result", structured_output=True, annotations=reading,
                 description="Register a binwitness.json made earlier (by the command line or another server) and "
                             "return its overview. Takes the file or the directory holding it. Sends nothing.")
    async def open_result(path: Annotated[str, Field(description="binwitness.json or its directory")]
                          ) -> dict[str, Any]:
        return await call(service.open_result, path)

    @server.tool(title="List scans", structured_output=True, annotations=reading,
                 description="Scans in the server's results directory and results opened in this session, newest "
                             "first. Sends nothing.")
    async def list_scans() -> dict[str, Any]:
        return await call(service.list_scans)

    @server.tool(title="Overview", structured_output=True, annotations=reading,
                 description="Coverage, counts by ecosystem, confidence and severity, the worst findings with "
                             "advice, upgrade verdicts and license families of a scan. Sends nothing.")
    async def overview(scan_id: ScanId) -> dict[str, Any]:
        return await call(service.overview, scan_id)

    @server.tool(title="List components", structured_output=True, annotations=reading,
                 description="Identified components in purl order, one line each (findings per severity, upgrade "
                             "verdict, license family, location count), paged. Sends nothing.")
    async def list_components(
            scan_id: ScanId,
            text: Annotated[str | None, Field(description="part of the purl, any case")] = None,
            min_severity: Severity = None,
            ecosystem: Annotated[Literal["maven", "npm"] | None, Field(description="only this ecosystem")] = None,
            license_family: Annotated[str | None, Field(description="e.g. permissive, weak-copyleft, "
                                                                    "strong-copyleft, unknown")] = None,
            verdict: Annotated[Literal[upgrades.VERDICTS] | None,  # type: ignore[valid-type]
                               Field(description="only components with this upgrade verdict")] = None,
            offset: Offset = 0, limit: Limit = PAGE) -> dict[str, Any]:
        return await call(service.list_components, scan_id, text, min_severity, ecosystem, license_family,
                          verdict, offset, limit)

    @server.tool(title="List unidentified jars", structured_output=True, annotations=reading,
                 description="Jars the scan could not name, with the reason, paged; these are outside the findings. "
                             "Sends nothing.")
    async def list_unidentified(scan_id: ScanId, offset: Offset = 0, limit: Limit = PAGE) -> dict[str, Any]:
        return await call(service.list_unidentified, scan_id, offset, limit)

    @server.tool(title="Component details", structured_output=True, annotations=reading,
                 description="One component: identification evidence, files and how they compare with the "
                             "published artifact, license, each finding with its fixed versions and advice, and "
                             "the upgrade advice. Sends nothing.")
    async def get_component(
            scan_id: ScanId,
            purl: Annotated[str, Field(description="the component's purl, its name (group:artifact, the artifactId "
                                                   "alone, an npm name) with or without @version; a part of a name "
                                                   "is answered with the names that contain it")],
            include_locations: Annotated[bool, Field(description=f"list where it was found (up to "
                                                                 f"{LOCATIONS_SHOWN})")] = False) -> dict[str, Any]:
        return await call(service.get_component, scan_id, purl, include_locations)

    @server.tool(title="Vulnerability details", structured_output=True,
                 annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                                             openWorldHint=service.config.lookup != "local"),
                 description="One finding of a scan (by CVE, GHSA or OSV id): severity, affected components with "
                             "advice, and the OSV record (details, ranges, references). The record comes from the "
                             "local datasets; when they lack it and the server allows lookups, the advisory id is "
                             "sent to api.osv.dev.")
    async def get_vulnerability(scan_id: ScanId,
                                vuln_id: Annotated[str, Field(description="CVE, GHSA or OSV id")]) -> dict[str, Any]:
        return await call(service.get_vulnerability, scan_id, vuln_id)

    @server.tool(title="Upgrade plan", structured_output=True, annotations=reading,
                 description="What to change, worst first: remove malicious packages, upgrade to the nearest "
                             "published version outside the advisories (one step and one target for the artifacts "
                             "of a release family), move to the new coordinates of a relocated artifact, replace "
                             "what has no published fix, or change the host jar of bundled components. Each step "
                             "lists what it clears, what remains and its caveats. Sends nothing.")
    async def upgrade_plan(scan_id: ScanId, min_severity: Severity = None, offset: Offset = 0,
                           limit: Limit = PAGE) -> dict[str, Any]:
        return await call(service.upgrade_plan, scan_id, min_severity, offset, limit)

    if service.config.lookup != "local":
        @server.tool(title="Cross-check another scanner", structured_output=True,
                     annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True,
                                                 openWorldHint=True),
                     description="Classify another scanner's findings (CycloneDX JSON, or CSV with columns "
                                 "component,version,vulnerability) against a scan, finding by finding. Sends the "
                                 "CVE and GHSA ids the two tools disagree on to GitHub's advisory API and the "
                                 "groupIds involved to OSV. Writes the full report next to the scan.")
        async def crosscheck(scan_id: ScanId,
                             other_path: Annotated[str, Field(description="the other tool's export, under the "
                                                                          "server's --root directories")],
                             limit: Annotated[int, Field(description="examples per class", ge=1)] = PAGE
                             ) -> dict[str, Any]:
            return await call(service.crosscheck, scan_id, other_path, limit)

    return server


def serve(service: Service):
    build_server(service).run(transport="stdio")
